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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
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
		
		DataTypeManager dtm = program.getDataTypeManager();
		if (dtm.getDataType(CategoryPath.ROOT, "__guard") == null) {
			StructureDataType guard = new StructureDataType("__guard", 8, dtm);
			DataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
			guard.replace(0, builtIn.getDataType(CategoryPath.ROOT, "byte"), 1, "initialized", "");
			guard.replace(1,  builtIn.getDataType(CategoryPath.ROOT, "byte"), 1, "in_use", "");
			dtm.addDataType(guard, null);
		}
		
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
		
		haveGuard = 0;
		noGuard = 0;
		monitor.setProgress(0);
		monitor.setMessage("Analyzing classes...");
		if (!analyzeClass(reflection, program, monitor)) { return false; }
		
		System.out.println("Have guards: "+haveGuard+" No guard: "+noGuard);
		
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
	
	private int haveGuard = 0;
	private int noGuard = 0;
	
	public boolean analyzeClass(Namespace cls, Program program, TaskMonitor monitor) {
		if (monitor.isCancelled()) { return false; }
		SymbolTable st = program.getSymbolTable();
		Listing listing = program.getListing();
		
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
		
		nonReqFuncs.removeIf(c -> getRequiredCallees(program).values().contains(c.function()));
		nonReqFuncs.removeIf(c -> c.function() == null);
		
		if (nonReqFuncs.size() > 2) {
			// Found a false positive; get rid of it
			st.removeSymbolSpecial(cls.getSymbol());
			return true;
		}
		
		for (FuncWithParams call: nonReqFuncs) {
			Function other = call.function();
			if (other == null) {
				System.out.println(cls.getName());
				continue;
			}
			if (other.getSymbol() != null && other.getSymbol().getSource() != SourceType.DEFAULT && !other.getName().equals(cls.getName())) { continue; }
			
			try {
				ArrayList<Reference> params = call.params();
				if (params.size() == 0) {
					resetFunction(program, other);
					continue; 
				}
				
				other.setParentNamespace(cls);
				other.addTag("CONSTRUCTOR");
				other.setName(cls.getName(), sourceType());
				other.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				
				updateThisDataType(program, other);
				
				Reference singleton = params.get(params.size()-1);

				DataType clsStruct = VariableUtilities.findExistingClassStruct(init);
				Data clsData = listing.getDataAt(singleton.getToAddress());
				if (clsData != null && clsData.getDataType() != clsStruct) {
					try {
						new FlatProgramAPI(program).removeData(clsData);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				if (clsData == null || clsData.getDataType() != clsStruct) {
					try {
						listing.createData(singleton.getToAddress(), clsStruct);
					} catch (CodeUnitInsertionException | DataTypeConflictException e1) {
						System.out.println("Overlapping object data: "+cls+" "+singleton.getToAddress());
					}
				}
				
				
				String name = cls.getName();
				if (name.startsWith("::")) { name = name.replaceFirst("::", ""); }
				st.getSymbol(singleton).setNameAndNamespace("_"+name, cls, sourceType());
				try {
					Reference singletonFlags = callsWithParams(program, init).get(0).params().get(0);
					if (st.getSymbol(singletonFlags).getName().equals("__guard")) { continue; }
					
					DataType guard = program.getDataTypeManager().getDataType(CategoryPath.ROOT, "__guard");
					Data sfData = listing.getDataAt(singletonFlags.getToAddress());
					if (sfData != null && sfData.getDataType() != guard) {
						try {
							new FlatProgramAPI(program).removeData(sfData);
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					if (sfData == null || sfData.getDataType() != guard) {
						try {
							listing.createData(singletonFlags.getToAddress(), guard);
						} catch (CodeUnitInsertionException | DataTypeConflictException e) {
							System.out.println("Overlapping __guard data: "+cls+" "+singletonFlags.getToAddress());
						}
					}
					st.getSymbol(singletonFlags).setNameAndNamespace("__guard", cls, sourceType());
					haveGuard++;
				} catch (IndexOutOfBoundsException e) {
					noGuard++;
//					System.out.println("No flag found: "+cls.getName());
				}
				
				if (params.size() < 2) { continue; }
				Address fieldsAddr = params.get(1).getToAddress();
				Function fields = findOrCreateFuncAt(program, fieldsAddr, "fields", cls);
				fields.setParentNamespace(cls);
				fields.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				// TODO: analyze fields
				
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
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
