package dread;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DreadReflectionNamespaceAnalyzer extends DreadAnalyzer {
	public DreadReflectionNamespaceAnalyzer() {
		super("(Dread) Generate Reflection Classes", "Analyzes functions in order to generate classes", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(priority(1));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		FunctionManager fm = program.getFunctionManager();
		final StringSearcher ss = new StringSearcher(program, 0, 1, true, true);
		SymbolTable st = program.getSymbolTable();
		
		Namespace reflection = reflection(program);
		if (reflection == null) { return false; }
		
		HashMap<String, Function> requiredCallees = getRequiredCallees(program);
		
		Pattern divideNamespaces = Pattern.compile("\\w+(?:<.*>)?(?:\\s*(?:const|\\*))*");
		
		int count = 0;
		for (@SuppressWarnings("unused") Function f : fm.getFunctions(set, true)) {
			count++;
		}
		
		monitor.setProgress(0);
		monitor.setMaximum(count);
		monitor.setIndeterminate(false);
		monitor.setMessage("Checking functions for reflection classes...");
		for (Function f : fm.getFunctions(set, true)) {
			if (monitor.isCancelled()) { return false; }
			monitor.incrementProgress(1);
			if (!forceReanalysis && f.getParentNamespace() != program.getGlobalNamespace()) { continue; }
			
			// must be a function with no arguments
			if (f.getParameterCount() > 0) { continue; }
			
			// ensure the function calls all the relevant functions used by the initializers
			Set<Function> called = f.getCalledFunctions(null);
			if (!called.containsAll(requiredCallees.values()) || requiredCallees.values().containsAll(called)) { continue; }
			
			ArrayList<FuncWithParams> rcvCalls = callsWithParams(program, f);
			rcvCalls.removeIf(fn -> fn.function() != requiredCallees.get("ReadConfigValue"));
			
			if (rcvCalls.size() == 0 || rcvCalls.get(0).params().size() == 0) { continue; }
			Address classNameAddr = rcvCalls.get(0).params().get(0).getToAddress();
			
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
			ss.search(new AddressSet(classNameAddr, set.getMaxAddress()), callback, false, stringMonitor);
			String fullName = nameBuilder.toString().trim();
			
			// ensure a class name could be found
			if (fullName.length() == 0) { 
				continue; 
			}
			
			// create classes
			try {
				if (forceReanalysis || f.getParentNamespace() == program.getGlobalNamespace()) {
					Namespace ns = reflection;
					Matcher matcher = divideNamespaces.matcher(fullName);
					
					while (matcher.find()) {
						String name = matcher.group().replace("*", "Ptr").replace(" ", "_");
						ns = st.getOrCreateNameSpace(ns, name, sourceType());
					}
					
					if (ns == reflection) {
						f.setParentNamespace(reflection);
					} else {
						GhidraClass cls = st.convertNamespaceToClass(ns);
						f.setParentNamespace(cls);
					}
				}
				f.setName("init", sourceType());
				f.addTag("REFLECTION");
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				e.printStackTrace();
				continue;
			}
		}
		return true;
	}
}
