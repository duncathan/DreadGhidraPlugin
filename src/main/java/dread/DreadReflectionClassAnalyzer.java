package dread;

import java.util.ArrayList;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DreadReflectionClassAnalyzer extends DreadAnalyzer {
	public DreadReflectionClassAnalyzer() {
		super("(Dread) Generate Type Hierarchy", "Analyzes the generated reflection classes to establish a hierearchy", AnalyzerType.FUNCTION_SIGNATURES_ANALYZER);
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
			if (hasTag(program, f, "REFLECTION")) { count++; }
		}
		monitor.setMaximum(count);
		monitor.setIndeterminate(false);
		
		monitor.setProgress(0);
		monitor.setMessage("Creating type hierarchy...");
		if (!createHierarchy(reflection, program, monitor)) { return false; }
		
		return true;
	}
	
	private boolean hasTag(Program program, Function f, String tag) {
		return hasTag(program, f, program.getFunctionManager().getFunctionTagManager().getFunctionTag(tag));
	}
	
	private boolean hasTag(Program program, Function f, FunctionTag tag) {
		return f.getTags().contains(tag);
	}
	
	private boolean createHierarchy(Namespace reflection, Program program, TaskMonitor monitor) {
		if (monitor.isCancelled()) { return false; }
		SymbolTable st = program.getSymbolTable();
		FunctionManager fm = program.getFunctionManager();
		
		for (Function f : fm.getFunctionsNoStubs(true)) {
			if (monitor.isCancelled()) { return false; }
			if (!hasTag(program, f, "REFLECTION")) { continue; }
			monitor.incrementProgress(1);
			if (hasTag(program, f, "PrimitiveType")) { continue; }
			
			if (f.getReturnType() == DataType.VOID) { continue; }
			if (f.getBody().getNumAddresses() == 1) {
				new CreateFunctionCmd(null, f.getEntryPoint(), null, sourceType(), false, true).applyTo(program);
				continue;
			}
			ArrayList<Reference> references = referencesFromFunc(program, f);
			ArrayList<Reference> dataRefs = new ArrayList<Reference>(references);
			dataRefs.removeIf(r -> r.getReferenceType() != RefType.DATA || r.isStackReference());
			if (dataRefs.size() == 1) {
				Reference singleton = dataRefs.get(0);
				try {
					f.setParentNamespace(st.getSymbol(singleton).getParentNamespace());
					f.setName("init", sourceType());
				} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
					// TODO Auto-generated catch block
//					e.printStackTrace();
				}
			} else if (hasTag(program, f, "CONSTRUCTOR")) {
				System.out.println("Inlined constructor: "+f);
			} else {
				ArrayList<FuncWithParams> calls = callsWithParams(program, f);
				calls.removeIf(fn -> !hasTag(program, fn.function(), "CONSTRUCTOR") || hasTag(program, fn.function(), "PrimitiveType"));
				if (calls.size() == 0) {
					System.out.println("uh oh "+f);
					continue;
				}
				try {
					f.setParentNamespace(calls.get(calls.size()-1).function().getParentNamespace());
					f.setName("init", sourceType());
				} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
					// TODO Auto-generated catch block
//					e.printStackTrace();
				}				
			}
			
			Namespace cls = f.getParentNamespace();
			if (cls == program.getGlobalNamespace() || cls == null) { continue; }
			Set<Function> called = f.getCalledFunctions(null);
			for (Function other : called) {
				
				// assign parent
				if (hasTag(program, other, "REFLECTION") && !hasTag(program, other, "PrimitiveType") && cls.getParentNamespace() != other.getParentNamespace()) {
					try {
						cls.setParentNamespace(other.getParentNamespace());
					} catch (InvalidInputException | DuplicateNameException | CircularDependencyException e) {
						// TODO Auto-generated catch block
//						e.printStackTrace();
					}
					break;
				}
			}
		}
		
//		for (Symbol s : st.getSymbols(reflection)) {
//			if (monitor.isCancelled()) { return false; }
//			if (!(s.getObject() instanceof GhidraClass)) { continue; }
//			GhidraClass cls = (GhidraClass) s.getObject();
//			
//			Function ctor = null;
//			for (Symbol s2 : st.getSymbols(cls)) {
//				if (!(s2.getObject() instanceof Function)) { continue; }
//				Function f = (Function) s2.getObject();
//				if (!hasTag(program, f, "ReflectionType")) { continue; }
//				ctor = f;
//				break;
//			}
//			if (ctor == null) { continue; }
//			
//			Set<Function> calling = ctor.getCallingFunctions(null);
//			if (calling.size() != 1) { continue; }
//			
//			monitor.incrementProgress(1);
//			
//			Function init = calling.iterator().next();
//
//			Set<Function> called = init.getCalledFunctions(null);
//			
//			called.removeIf(fn -> !hasTag(program, fn, "ReflectionType"));
//			if (called.size() != 1) { continue; }
//			
//			called = init.getCalledFunctions(null);
//			
//			if (!forceReanalysis && cls.getParentNamespace() != reflection) {
//				continue;
//			}
//			
//			try {
//				init.setName("init", sourceType());
//				init.setParentNamespace(cls);
//			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e1) {
//				// TODO Auto-generated catch block
//				e1.printStackTrace();
//			}
//			
//			
//		}
		return true;
	}
}
