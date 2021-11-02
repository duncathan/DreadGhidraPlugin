package dread;

import java.util.ArrayList;
import java.util.Set;

import ghidra.app.decompiler.ClangFuncProto;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableDecl;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DreadReflectionClassAnalyzer extends DreadAnalyzer {
	public DreadReflectionClassAnalyzer() {
		super("(Dread) Analyze Reflection Classes", "Analyzes the generated reflection classes to establish a hierearchy and identify class functions", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(priority(2));
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
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
		if (monitor.isCancelled()) { return false; }
		SymbolTable st = program.getSymbolTable();
		
		for (Symbol s : st.getSymbols(reflection)) {
			if (s.getParentNamespace() != reflection) { continue; }
			if (!(s.getObject() instanceof GhidraClass)) { continue; }
			
			GhidraClass cls = (GhidraClass) s.getObject();
			Function init = null;
			for (Symbol c : st.getSymbols(cls)) {
				if (c.getName().startsWith("init")) {
					init = (Function) c.getObject();
					break;
				}
			}
			if (init == null) { continue; }
			
			if (!forceReanalysis && cls.getParentNamespace() != program.getGlobalNamespace()) {
				continue;
			}
			
			monitor.incrementProgress(1);
			
			Set<Function> called = init.getCalledFunctions(null);
			
			for (Function other : called) {
				
				// assign parent
				if (other.getName().startsWith("init") && cls.getParentNamespace() != other.getParentNamespace()) {
					try {
						try {
							cls.setParentNamespace(other.getParentNamespace());
						} catch (DuplicateNameException e) {
							for (Symbol s2 : st.getSymbols(cls.getName(), other.getParentNamespace())) {
								st.removeSymbolSpecial(s2);
							}
							cls.setParentNamespace(other.getParentNamespace());
						}
					} catch (InvalidInputException | DuplicateNameException | CircularDependencyException e) {
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
		if (monitor.isCancelled()) { return false; }
		SymbolTable st = program.getSymbolTable();
		
		for (Symbol s : st.getSymbols(cls)) {
			Object o = s.getObject();
			if (o instanceof Namespace) {
				if (!analyzeClass((Namespace) o, program, monitor)) { return false; }
			}
		}
		
		Function init;
		try {
			init = (Function) st.getSymbols("init", cls).get(0).getObject();
		} catch (IndexOutOfBoundsException e) {
			return true; // no constructor
		}
		
		monitor.incrementProgress(1);
		
		ArrayList<FuncWithParams> nonReqFuncs = callsWithParams(program, init);
		
		for (Function req : getRequiredCallees(program).values()) {
			ArrayList<FuncWithParams> remove = new ArrayList<FuncWithParams>();
			for (FuncWithParams call : nonReqFuncs) {
				if (req == call.function()) {
					remove.add(call);
				}
			}
			nonReqFuncs.removeAll(remove);
		}
		
		if (nonReqFuncs.size() > 2) {
			// Found a false positive; get rid of it
			st.removeSymbolSpecial(cls.getSymbol());
			return true;
		}
		
		for (FuncWithParams call: nonReqFuncs) {
			Function other = call.function();
			if (other.getSymbol() != null && other.getSymbol().getSource() != SourceType.DEFAULT && !other.getName().equals(cls.getName())) { continue; }
			
			try {
				other.setParentNamespace(cls);
				other.addTag("CONSTRUCTOR");
				other.setName(cls.getName(), sourceType());
				other.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				
				updateThisDataType(program, other);
				
				ArrayList<Reference> params = call.params();
				if (params.size() == 0) { continue; }
				
				Reference singleton = params.get(params.size()-1);
				Symbol singletonData = st.getSymbol(singleton);
				
				String name = cls.getName();
				if (name.startsWith("::")) { name = name.replaceFirst("::", ""); }
				singletonData.setNameAndNamespace("_"+name, cls, sourceType());
				try {
					Symbol singletonFlags = st.getSymbols(singleton.getToAddress().subtract(8))[0];
					singletonFlags.setNameAndNamespace("f_"+name, cls, sourceType());
				} catch (IndexOutOfBoundsException e) {
//					System.out.println("No flag found: "+cls.getName());
				}
				
				if (params.size() < 2) { continue; }
				Address fieldsAddr = params.get(1).getToAddress();
				Function fields = functionAt(program, fieldsAddr);
				if (fields == null) {
					fields = new UndefinedFunction(program, fieldsAddr);
					fields = program.getFunctionManager().createFunction("fields", cls, fieldsAddr, fields.getBody(), SourceType.ANALYSIS);
				}
				fields.setParentNamespace(cls);
				fields.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				// TODO: analyze fields
				
				
				
				

			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException | OverlappingFunctionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return false;
			}
			break;
		}
		return true;
	}
	
	boolean updateThisDataType(Program program, Function function) {
		Structure cls = VariableUtilities.findExistingClassStruct(function);
		
		if (cls.isNotYetDefined()) {
			DecompInterface di = new DecompInterface();
			di.openProgram(program);
			
			DecompileResults res = di.decompileFunction(function, 45, null);
			if (!res.decompileCompleted()) {
				System.out.println(res.getErrorMessage());
				return false;
			}
			
			ClangTokenGroup g = res.getCCodeMarkup().getClangFunction();
			DecompilerLocation thisLoc = null;
			for (int i = 0; thisLoc == null && i < g.numChildren(); i++) {
				ClangNode proto = g.Child(i);
				if (proto instanceof ClangFuncProto) {
					for (int j = 0; thisLoc == null && j < proto.numChildren(); j++) {
						ClangNode child = proto.Child(j);
						if (child instanceof ClangVariableDecl) {
							ClangVariableToken thisVar = null;
							for (int k = 0; k < child.numChildren(); k++) {
								ClangNode var = child.Child(k);
								if (var instanceof ClangVariableToken) {
									thisVar = (ClangVariableToken) var;
									break;
								}
							}
							HighSymbol thisSym = thisVar.getHighVariable().getSymbol();
							if (!thisSym.isThisPointer()) { continue; }
							thisLoc = new DecompilerLocation(program, thisSym.getHighFunction().getFunction().getEntryPoint(), thisSym.getHighFunction().getFunction().getEntryPoint(), res, thisVar, 0, 0);
						}
					}
				}
			}
			if (thisLoc == null) {
				System.out.println("No this pointer found: "+function.getParentNamespace());
				return false;
			}
			new FillOutStructureCmd(program, thisLoc, null).applyTo(program);
		}
		
		
		try {
			// TODO: tackle some specific fields?
			cls.replace(0, new Pointer64DataType(new VoidDataType()), 8, "_vptr", "Virtual table pointer");
		} catch (IndexOutOfBoundsException e) {
			System.out.println("No fields in data type: "+cls.getName());
			return false;
		}
			
		
		return true;
	}
}
