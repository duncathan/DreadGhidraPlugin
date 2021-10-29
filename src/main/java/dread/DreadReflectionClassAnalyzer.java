package dread;

import java.util.Set;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
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
		
		Namespace reflection = reflection(program);
		if (reflection == null) { return false; }
		
		int count = 0;
		SymbolIterator _ref = st.getSymbols(reflection);
		while (_ref.hasNext()) {
			count++;
			_ref.next();
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
			Function get = (Function) st.getSymbols("get", cls).get(0).getObject();
			
			Set<Function> called = get.getCalledFunctions(null);
			
			for (Function other : called) {
				
				// assign parent
				if (other.getName().equals("get") && get.getParentNamespace().getParentNamespace() != other.getParentNamespace()) {
					try {
						get.getParentNamespace().setParentNamespace(other.getParentNamespace());
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
		AddressFactory af = program.getAddressFactory();
		FunctionManager fm = program.getFunctionManager();
		
		monitor.incrementProgress(1);
		System.out.println(cls.getName());
		
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
			return true;
		}
		
		Set<Function> called = get.getCalledFunctions(null);
		called.removeAll(getRequiredCallees(fm, af).values());
		
		for (Function other : called) {
			if (other.getName().equals("get")) { continue; }
			
			try {
				// FIXME: identify the constructor properly please lol
				other.setParentNamespace(cls);
				other.addTag("CONSTRUCTOR");
				other.setName(cls.getName(), SourceType.ANALYSIS);
				
//				Parameter[] params = other.getParameters();
//				params[0].setName("this", SourceType.ANALYSIS);
//				other.updateFunction(CompilerSpec.CALLING_CONVENTION_thiscall,
//						null, Arrays.asList(params),
//						Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
//						false, SourceType.ANALYSIS);
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
			break;
		}
		return true;
	}
}
