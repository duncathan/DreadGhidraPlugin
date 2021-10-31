package dread;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
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
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS);
	}
	
	private boolean forceReanalysis = false;
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption("Force re-analysis", forceReanalysis, null,
			"Re-analyze even if a class has already been created");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		forceReanalysis = options.getBoolean("Force re-analysis", forceReanalysis);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		FunctionManager fm = program.getFunctionManager();
		ReferenceManager rm = program.getReferenceManager();
		final StringSearcher ss = new StringSearcher(program, 0, 1, true, true);
		SymbolTable st = program.getSymbolTable();
		
		Namespace reflection = reflection(program);
		if (reflection == null) { return false; }
		
		HashMap<String, Function> requiredCallees = getRequiredCallees(program);
		Pattern validNames = Pattern.compile("(?:\\w+(?:::)?)+");
		
		int count = 0;
		for (Function f : fm.getFunctions(set, true)) {
			count++;
		}
		
		monitor.setProgress(0);
		monitor.setMaximum(count);
		monitor.setIndeterminate(false);
		monitor.setMessage("Checking functions for reflection classes...");
		for (Function f : fm.getFunctions(set, true)) {
			monitor.incrementProgress(1);
			if (!forceReanalysis && f.getParentNamespace() != program.getGlobalNamespace()) { continue; }
			
			// must be a function with no arguments
			if (f.getParameterCount() > 0) { continue; }
			
			// ensure the function calls all the relevant functions used by the initializers
			Set<Function> called = f.getCalledFunctions(null);
			if (!called.containsAll(requiredCallees.values())) { continue; }
			
			// find all outgoing references from this function
			ArrayList<Reference> references = new ArrayList<Reference>();
			for (Address a : rm.getReferenceSourceIterator(f.getBody(), true))  {
				references.addAll(Arrays.asList(rm.getReferencesFrom(a)));
			}
			
			// find the address of the class name string
			ArrayList<Reference> paramReferences = new ArrayList<Reference>(references.stream().filter(r -> r.getReferenceType() == RefType.PARAM).collect(Collectors.toList()));
			Address classNameAddr = paramReferences.get(1).getToAddress();
			
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
			if (fullName.length() == 0 || !validNames.matcher(fullName).matches()) { continue; }
			
			// create classes
			try {
				if (f.getParentNamespace() != program.getGlobalNamespace()) {
					Namespace ns = reflection;
					for (String s : fullName.split("::")) {
						ns = st.getOrCreateNameSpace(ns, s, SourceType.ANALYSIS);
					}
					
					GhidraClass cls = st.convertNamespaceToClass(ns);
					
					f.setParentNamespace(cls);
				}
				f.setName("init", SourceType.ANALYSIS);
				f.addTag("REFLECTION");
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				e.printStackTrace();
				continue;
			}
		}
		return true;
	}
}
