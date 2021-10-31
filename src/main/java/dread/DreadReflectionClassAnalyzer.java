package dread;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Set;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DreadReflectionClassAnalyzer extends DreadAnalyzer {
	public DreadReflectionClassAnalyzer() {
		super("(Dread) Analyze Reflection Classes", "Analyzes the generated reflection classes to establish a hierearchy and identify class functions", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		SymbolTable st = program.getSymbolTable();
		FunctionManager fm = program.getFunctionManager();
		
		Namespace reflection = reflection(program);
		if (reflection == null) { return false; }
		
		int count = 0;
		for (Function f : fm.getFunctions(set, true)) {
			for (FunctionTag t : f.getTags()) {
				if (t.getName().equals("REFLECTION")) {
					count++;
					break;
				}
			}
		}
		monitor.setMaximum(count);
		monitor.setIndeterminate(false);
		
		monitor.setProgress(0);
		monitor.setMessage("Creating type hierarchy...");
		if (!createHierarchy(reflection, program, monitor)) { return false; }
		
		monitor.setProgress(0);
		monitor.setMessage("Analyzing classes...");
		if (!analyzeClass(reflection, program, monitor)) { return false; }
		
		return true;
	}
	
	private boolean createHierarchy(Namespace reflection, Program program, TaskMonitor monitor) {
		SymbolTable st = program.getSymbolTable();
		
		for (Symbol s : st.getSymbols(reflection)) {
			if (s.getParentNamespace() != reflection) { continue; }
			if (!(s.getObject() instanceof GhidraClass)) { continue; }
			
			monitor.incrementProgress(1);
			
			GhidraClass cls = (GhidraClass) s.getObject();
			Function init = null;
			for (Symbol c : st.getSymbols(cls)) {
				if (c.getName().startsWith("init")) {
					init = (Function) c.getObject();
					break;
				}
			}
			if (init == null) { continue; }
			
			if (init.getParentNamespace().getParentNamespace() != program.getGlobalNamespace()) {
				continue;
			}
			
			Set<Function> called = init.getCalledFunctions(null);
			
			for (Function other : called) {
				
				// assign parent
				if (other.getName().startsWith("init") && init.getParentNamespace().getParentNamespace() != other.getParentNamespace()) {
					try {
						init.getParentNamespace().setParentNamespace(other.getParentNamespace());
					} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					break;
				}
			}
		}
		return true;
	}
	
	public boolean analyzeClass(Namespace cls, Program program, TaskMonitor monitor) {
		SymbolTable st = program.getSymbolTable();
		ReferenceManager rm = program.getReferenceManager();
		
		monitor.incrementProgress(1);
		
		for (Symbol s : st.getSymbols(cls)) {
			Object o = s.getObject();
			if (o instanceof Namespace) {
				if (!analyzeClass((Namespace) o, program, monitor)) { return false; }
			}
		}
		
		Function get;
		try {
			get = (Function) st.getSymbols("get", cls).get(0).getObject();
		} catch (IndexOutOfBoundsException e) {
			return true; // no constructor
		}
		
		ArrayList<Reference> allReferences = new ArrayList<Reference>();
		for (Address a : rm.getReferenceSourceIterator(get.getBody(), true)) {
			allReferences.addAll(Arrays.asList(rm.getReferencesFrom(a)));
		}
		
		LinkedHashMap<Function, ArrayList<Reference>> funcsWithParams = new LinkedHashMap<Function, ArrayList<Reference>>();
		ArrayList<Reference> params = new ArrayList<Reference>();
		for (Reference r : allReferences) {
			if (r.getReferenceType() == RefType.PARAM) {
				params.add(r);
			}
			else if ((r.getReferenceType() instanceof FlowType) && ((FlowType) r.getReferenceType()).isCall()) {
				funcsWithParams.put(functionAt(program, r.getToAddress()), params);
				params = new ArrayList<Reference>();
			}
		}
		
		LinkedHashMap<Function, ArrayList<Reference>> nonReqFuncs = new LinkedHashMap<Function, ArrayList<Reference>>(funcsWithParams);
		for (Function req : getRequiredCallees(program).values()) {
			nonReqFuncs.remove(req);
		}
		
		if (nonReqFuncs.size() > 2) { return true; }
		
		for (Function other : nonReqFuncs.keySet()) {
			if (other.getName().startsWith("get")) { continue; }
			
			try {
				other.setParentNamespace(cls);
				other.addTag("CONSTRUCTOR");
				other.setName(cls.getName(), sourceType());
				other.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				
				ArrayList<Reference> p = nonReqFuncs.get(other);
				
				if (p.size() < 2) { continue; }
				Address fieldsAddr = p.get(1).getToAddress();
				Function fields = functionAt(program, fieldsAddr);
				if (fields == null) {
					fields = new UndefinedFunction(program, fieldsAddr);
					fields = program.getFunctionManager().createFunction("fields", cls, fieldsAddr, fields.getBody(), SourceType.ANALYSIS);
				}
				fields.setParentNamespace(cls);
				fields.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				// TODO: analyze fields
				
				Reference singleton = p.get(p.size()-1);
				Symbol singletonData = st.getSymbol(singleton);
				singletonData.setName("_"+cls.getName(), sourceType());
				try {
					Symbol singletonFlags = st.getSymbols(singleton.getToAddress().subtract(8))[0];
					singletonFlags.setName("f_"+cls.getName(), sourceType());
				} catch (IndexOutOfBoundsException e) {
					System.out.println(cls.getName());
					continue;
				}

			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException | OverlappingFunctionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
			break;
		}
		return true;
	}
}
