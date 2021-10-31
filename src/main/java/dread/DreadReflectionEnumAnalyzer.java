package dread;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.collections4.IteratorUtils;

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
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DreadReflectionEnumAnalyzer extends DreadAnalyzer {
	public DreadReflectionEnumAnalyzer() {
		super("(Dread) Generate Enum Classes", "Analyzes functions in order to generate enums", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(priority(1));
	}
	
	private boolean forceReanalysis = false;
	
	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);
		options.registerOption("Force re-analysis", forceReanalysis, null,
			"Re-analyze even if a class has already been created");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		forceReanalysis = options.getBoolean("Force re-analysis", forceReanalysis);
	}
	
	private ArrayList<Reference> filterReferenceIterator(ReferenceIterator iterator, RefType type) {
		ArrayList<Reference> result = new ArrayList<Reference>();
		for (Reference ref : iterator) {
			if (ref.getReferenceType() == type) {
				result.add(ref);
			}							
		}
		return result;
	}
	
	private ArrayList<Reference> filterReferenceIterator(Reference[] iterator, RefType type) {
		ArrayList<Reference> result = new ArrayList<Reference>();
		for (Reference ref : iterator) {
			if (ref.getReferenceType() == type) {
				result.add(ref);
			}							
		}
		return result;
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

		Function addEnumValue = getRequiredCallees(program).get("AddEnumValue");
		Set<Function> calling = addEnumValue.getCallingFunctions(null);

		monitor.setProgress(0);
		monitor.setMaximum(calling.size());
		monitor.setIndeterminate(false);
		
		for (Function f : calling) {
			monitor.incrementProgress(1);
			if (!forceReanalysis && f.getParentNamespace() != program.getGlobalNamespace()) { continue; }
			
			// Find the simple usage via PARAM
			ArrayList<Reference> usageRefs = filterReferenceIterator(rm.getReferencesTo(f.getEntryPoint()), RefType.PARAM);
			if (usageRefs.size() != 1) {
				// Multiple references to this function, ignore.
				System.out.println(f.getEntryPoint().toString() + " ignored for invalid number of references.");
				continue;
			}
			Reference usage = usageRefs.get(0);
			Address fromUsage = usage.getFromAddress();

			Address hashStrCall = fromUsage.subtract(0x10);
			ArrayList<Reference> hashCallRefs = filterReferenceIterator(rm.getReferencesFrom(hashStrCall), RefType.UNCONDITIONAL_CALL);
			if (hashCallRefs.size() != 1) {
				// TODO: check if the target address is 0x71000003d4
				System.out.println(f.getEntryPoint().toString() + " ignored, couldn't find call to HashStr.");
				continue;
			}
			
//			ArrayList<Reference> stringRefs = new ArrayList<Reference>();
//			for (int offset = 0xC; offset < )
			Address nameRef = hashStrCall.subtract(0xC);
			ArrayList<Reference> stringRefs = filterReferenceIterator(rm.getReferencesFrom(nameRef), RefType.PARAM);
			System.out.println(fromUsage + " to " + stringRefs);
		}
		return true;
	}
}
