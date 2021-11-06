package dread;

import java.util.Set;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
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
			for (FunctionTag t : f.getTags()) {
				if (t.getName().equals("CONSTRUCTOR")) {
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
		
		for (Symbol s : st.getSymbols(reflection)) {
			if (monitor.isCancelled()) { return false; }
			if (!(s.getObject() instanceof GhidraClass)) { continue; }
			GhidraClass cls = (GhidraClass) s.getObject();
			
			Function ctor = null;
			for (Symbol s2 : st.getSymbols(cls)) {
				if (!(s2.getObject() instanceof Function)) { continue; }
				Function f = (Function) s2.getObject();
				if (!hasTag(program, f, "ReflectionType")) { continue; }
				ctor = f;
				break;
			}
			if (ctor == null) { continue; }
			
			Set<Function> calling = ctor.getCallingFunctions(null);
			if (calling.size() != 1) { continue; }
			
			monitor.incrementProgress(1);
			
			Function init = calling.iterator().next();

			Set<Function> called = init.getCalledFunctions(null);
			
			called.removeIf(fn -> !hasTag(program, fn, "ReflectionType"));
			if (called.size() != 1) { continue; }
			
			called = init.getCalledFunctions(null);
			
			if (!forceReanalysis && cls.getParentNamespace() != reflection) {
				continue;
			}
			
			try {
				init.setName("init", sourceType());
				init.setParentNamespace(cls);
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
			for (Function other : called) {
				
				// assign parent
				if (hasTag(program, other, "REFLECTION") && cls.getParentNamespace() != other.getParentNamespace()) {
					try {
						cls.setParentNamespace(other.getParentNamespace());
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
}
