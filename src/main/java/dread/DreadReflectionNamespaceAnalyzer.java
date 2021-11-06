package dread;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
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
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DreadReflectionNamespaceAnalyzer extends DreadAnalyzer {
	public DreadReflectionNamespaceAnalyzer() {
		super("(Dread) Generate Reflection Classes", "Analyzes functions in order to generate classes", AnalyzerType.BYTE_ANALYZER);
		setPriority(priority(1));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		ReferenceManager rm = program.getReferenceManager();
		AddressFactory af = program.getAddressFactory();
		Listing listing = program.getListing();
		SymbolTable st = program.getSymbolTable();
		FlatProgramAPI flatAPI = new FlatProgramAPI(program);
		
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
		
		HashMap<String, Function> knownFuncs = knownFunctions(program);
		
		Pattern divideNamespaces = Pattern.compile("\\w+(?:<.*>)?(?:\\s*(?:const|\\*))*");
		
		Map<String, Address> baseReflectionTypes = Map.of(
				"CClass", 			af.getAddress("0x71015df6f7"),	// 2922
				"CPointerType", 	af.getAddress("0x7101577e71"),	// 1152
				"CEnumType", 		af.getAddress("0x71015e9811"),	// 238
				"CCollectionType", 	af.getAddress("0x710156db4e"),	// 205
				"CFlagsetType", 	af.getAddress("0x71015d03dd")	// 9
		);
		
		HashMap<String, Integer> baseTypeReferences = new HashMap<String, Integer>();
		HashMap<String, Integer> baseTypeConstructorCount = new HashMap<String, Integer>();
		for (String baseTypeName : baseReflectionTypes.keySet()) {
			Address baseTypeString = baseReflectionTypes.get(baseTypeName);
			baseTypeReferences.put(baseTypeName, rm.getReferenceCountTo(baseTypeString));
			baseTypeConstructorCount.put(baseTypeName, 0);
			
			monitor.setProgress(0);
			monitor.setMaximum(baseTypeReferences.get(baseTypeName));
			monitor.setIndeterminate(false);
			monitor.setMessage("Creating "+baseTypeName+" reflection classes...");
			
			for (Reference r : rm.getReferencesTo(baseTypeString)) {
				if (monitor.isCancelled()) { return false; }
				monitor.incrementProgress(1);
				
				Function f = findOrCreateFuncContaining(program, r.getFromAddress());
				if (!forceReanalysis && f.getParentNamespace() != program.getGlobalNamespace()) {
					baseTypeConstructorCount.put(baseTypeName, baseTypeConstructorCount.get(baseTypeName)+1);
					continue;
				}
				
				Set<Function> called = f.getCalledFunctions(null);
				
				if (!called.contains(knownFuncs.get("CRC64"))) { continue; }
				// calls CRC64; definitely a constructor
				
				boolean inline = false;
				FuncWithParams hashStr = null;
				if (called.contains(knownFuncs.get("__cxa_guard_acquire"))) {
					//inline constructor
					inline = true;
					
					f.addTag("REFLECTION");
					
					ArrayList<FuncWithParams> hashStrCalls = callsWithParams(program, f);
					hashStrCalls.removeIf(fn -> fn.function() != knownFuncs.get("HashString"));
					if (hashStrCalls.size() > 0) {
						hashStr = hashStrCalls.get(0);
					}
				} else {
					// standard constructor
					Function init = getCaller(program, f);
					init.addTag("REFLECTION");
					
					ArrayList<FuncWithParams> allCalls = callsWithParams(program, init);
					
					FuncWithParams thiscall = null;
					for (FuncWithParams call : allCalls) {
						if (call.function() == f) { 
							thiscall = call;
							break;
						}
					}
						
					hashStr = allCalls.get(allCalls.indexOf(thiscall)-1);
					ArrayList<Function> hashStrOrCrc = new ArrayList<Function>();
					hashStrOrCrc.add(knownFuncs.get("HashString"));
					hashStrOrCrc.add(knownFuncs.get("CRC64"));
					for (int i = allCalls.indexOf(hashStr)-1; i >= 0 && !hashStrOrCrc.contains(hashStr.function()); i--) {
						hashStr = allCalls.get(i);
					}
				}
						
				Address classNameAddr = hashStr.params().get(0).getToAddress();

				String fullName = findName(program, classNameAddr);
				
				String[] constrTags = {"CONSTRUCTOR", "ReflectionType", baseTypeName};
				createFunc(program, f, divideNamespaces, fullName, null, constrTags);
				try {
					f.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
				} catch (InvalidInputException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				baseTypeConstructorCount.put(baseTypeName, baseTypeConstructorCount.get(baseTypeName)+1);
				
				if (!inline) {
					Function init = getCaller(program, f);
					FuncWithParams thisCall = null;
					for (FuncWithParams call : callsWithParams(program, init)) {
						if (call.function() == f) {
							thisCall = call;
							break;
						}
					}
					
					updateThisDataType(program, f);
					
					ArrayList<Reference> params = thisCall.params();
					GhidraClass cls = (GhidraClass) f.getParentNamespace();
					
					Reference singleton = null;
					for (Reference param : params) {
						if (flatAPI.getMemoryBlock(param.getToAddress()).getName().equals(".bss")) {
							singleton = param;
							break;
						}
					}
					params.remove(singleton);
					
					if (singleton != null) {

						DataType clsStruct = VariableUtilities.findExistingClassStruct(f);
						Data clsData = listing.getDataAt(singleton.getToAddress());
						if (clsData != null && clsData.getDataType() != clsStruct) {
							try {
								flatAPI.removeData(clsData);
							} catch (Exception e) {
								e.printStackTrace();
							}
						}
						if (clsData == null || clsData.getDataType() != clsStruct) {
							try {
								listing.createData(singleton.getToAddress(), clsStruct);
							} catch (CodeUnitInsertionException | DataTypeConflictException e1) {
	//							System.out.println("Overlapping object data: "+cls+" "+singleton.getToAddress());
							} catch (NullPointerException e2) {
								System.out.println("No singleton found: "+cls);
								break;
							}
						}
						
						
						String name = cls.getName();
						if (name.startsWith("::")) { name = name.replaceFirst("::", ""); }
						try {
							st.getSymbol(singleton).setNameAndNamespace("_"+name, cls, sourceType());
						} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						
						switch (baseTypeName) {
							case "CClass":
								ArrayList<FuncWithParams> guardCalls = callsWithParams(program, init);
								guardCalls.removeIf(fn -> fn.function() != knownFuncs.get("__cxa_guard_acquire"));
								if (guardCalls.size() > 0) {
									Reference singletonGuards = guardCalls.get(0).params().get(0);
									if (singletonGuards == null || st.getSymbol(singletonGuards).getName().equals("__guard")) { break; }
									
									DataType guard = program.getDataTypeManager().getDataType(CategoryPath.ROOT, "__guard");
									Data sfData = listing.getDataAt(singletonGuards.getToAddress());
									if (sfData != null && sfData.getDataType() != guard) {
										try {
											flatAPI.removeData(sfData);
										} catch (Exception e) {
											e.printStackTrace();
										}
									}
									if (sfData == null || sfData.getDataType() != guard) {
										try {
											listing.createData(singletonGuards.getToAddress(), guard);
										} catch (CodeUnitInsertionException | DataTypeConflictException e) {
											System.out.println("Overlapping __guard data: "+cls+" "+singletonGuards.getToAddress());
										}
									}
									try {
										st.getSymbol(singletonGuards).setNameAndNamespace("__guard", cls, sourceType());
									} catch (DuplicateNameException | InvalidInputException
											| CircularDependencyException e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}
								}
								
								Function fields = null;
								for (Reference param : params) {
									Address addr = param.getToAddress();
									Function possibleFields = findOrCreateFuncAt(program, addr, cls);
									if (possibleFields == null) { continue; }
									try {
										possibleFields.setParentNamespace(cls);
										possibleFields.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
									} catch (InvalidInputException | CircularDependencyException | DuplicateNameException e) {
										e.printStackTrace();
									}
										if (!possibleFields.getCalledFunctions(null).contains(knownFuncs.get("RegisterField"))) { continue; }
									fields = possibleFields;
									break;
								}
								if (fields == null) {
									// this class's fields func is empty
//									System.out.println("Missing fields func: "+cls.getName());
									break;
								}
								try {
									fields.setName("fields", sourceType());
								} catch (DuplicateNameException | InvalidInputException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								break;
							
							case "CPointerType":
								break;
							
							case "CEnumType":
								if (params.size() < 1) { break; }
								Address valuesAddr = params.get(params.size()-1).getToAddress();
								Function values = findOrCreateFuncAt(program, valuesAddr, "values", cls);
								if (values == null) {
									System.out.println("Missing values func: "+cls.getName());
									break;
								}
								try {
									values.setParentNamespace(cls);
									values.setName("values", sourceType());
									values.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);
								} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
								break;
							
							case "CCollectionType":
								break;
							
							case "CFlagsetType":
								break;
						}
					}
				}
			}
		}
		
		String warning = "";
		for (String baseTypeName : baseReflectionTypes.keySet()) {
			int difference = baseTypeReferences.get(baseTypeName) - baseTypeConstructorCount.get(baseTypeName) - 1;
			if (difference > 0) {
				warning = warning+difference+" "+baseTypeName+" constructors failed to be analyzed properly.\n";
			}
		}
		if (warning.length() > 0) {
			Msg.showWarn(this.getClass(), null, "Constructors missing!", warning);
		}
		
		return true;
	}
	
	public Function getCaller(Program program, Function f) {
		Set<Function> calling = new HashSet<Function>(); 
		for (Reference r2 : program.getReferenceManager().getReferencesTo(f.getEntryPoint())) {
			if (r2.getReferenceType() != RefType.UNCONDITIONAL_CALL) { continue; }
			calling.add(findOrCreateFuncContaining(program, r2.getFromAddress()));
		}
		
		return calling.iterator().next();
	}
	
	public boolean createFunc(Program program, Function f, Pattern p, String fullName, String funcName, String[] tags) {
		// create classes
		try {
			if (forceReanalysis || f.getParentNamespace() == program.getGlobalNamespace()) {
				Namespace reflection = reflection(program);
				Namespace ns = reflection;
				Matcher matcher = p.matcher(fullName);
				
				while (matcher.find()) {
					String name = matcher.group().replace("*", "Ptr").replace(" ", "_");
					ns = program.getSymbolTable().getOrCreateNameSpace(ns, name, sourceType());
				}
				
				if (ns == reflection) {
					f.setParentNamespace(reflection);
				} else {
					GhidraClass cls = program.getSymbolTable().convertNamespaceToClass(ns);
					f.setParentNamespace(cls);
				}
			}
			if (funcName == null) { funcName = f.getParentNamespace().getName(); }
			f.setName(funcName, sourceType());
			
			for (String tag : tags) {
				f.addTag(tag);
			}
		} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public String findName(Program program, Address addr) {
		// search for the class name referenced by the function
		final DummyCancellableTaskMonitor stringMonitor = new DummyCancellableTaskMonitor();
		final StringBuilder nameBuilder = new StringBuilder();
		FoundStringCallback callback = new FoundStringCallback() {
			public void stringFound(FoundString foundString) {
				String s = foundString.getString(program.getMemory());
				nameBuilder.setLength(s.length());
				nameBuilder.insert(0, s);
				stringMonitor.cancel();
			}
		};
		final StringSearcher ss = new StringSearcher(program, 0, 1, true, true);
		ss.search(new AddressSet(addr, program.getMaxAddress()), callback, false, stringMonitor);
		return nameBuilder.toString().trim();
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
