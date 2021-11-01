package dread;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
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
	
	private String getFirstStringParam(Address initialAddress, ReferenceManager rm, Listing listing) {
		for (int offset = 4; offset < 0x100; offset += 4) {
			for (Reference ref : rm.getReferencesFrom(initialAddress.subtract(offset))) {
				if (ref.getReferenceType() == RefType.PARAM) {
					Data it = listing.getDataAt(ref.getToAddress());
					if (it != null && it.getDataType().toString() == "string") {
						return (String) it.getValue();
					}				
				}
			}
		}
		return null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		FunctionManager fm = program.getFunctionManager();
		ReferenceManager rm = program.getReferenceManager();
		Listing listing = program.getListing();
		
		Namespace reflection = reflection(program);
		if (reflection == null) { return false; }

		monitor.setProgress(0);
		monitor.setIndeterminate(false);
		
		Address s_Invalid = program.getAddressFactory().getAddress("0x71015a077c");
		int count = 0;
		for (Reference r : rm.getReferencesTo(s_Invalid)) {
			count++;
		}
		monitor.setMaximum(count);
		for (Reference r : rm.getReferencesTo(s_Invalid)) {
			Function f = getOrCreateFunctionFor(program, r.getFromAddress());

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
			
			// Find the DAT
			Address datAddress = fromUsage.add(0x8);
			ArrayList<Reference> datRefs = filterReferenceIterator(rm.getReferencesFrom(datAddress), RefType.PARAM);
//			System.out.println(f.getEntryPoint().toString() + " dat " + datRefs);
			// TODO: this sometimes misses, not good.
			
			// Find the type name, via the argument to HashStr
			Address hashStrCall = fromUsage.subtract(0x10);
			ArrayList<Reference> hashCallRefs = filterReferenceIterator(rm.getReferencesFrom(hashStrCall), RefType.UNCONDITIONAL_CALL);
			if (hashCallRefs.size() != 1) {
				// TODO: check if the target address is 0x71000003d4
				System.out.println(f.getEntryPoint().toString() + " ignored, couldn't find call to HashStr.");
				continue;
			}
			String typeString = getFirstStringParam(hashStrCall, rm, listing);
			if (typeString == null) {
				continue;
			}
			// typeString is what we want! YAY
			
			System.out.println(f.getEntryPoint().toString() + " is for " + typeString);
		}
		return true;
	}

	private Function getOrCreateFunctionFor(Program program, Address refToInvalidStr) {
		FunctionManager fm = program.getFunctionManager();
		ReferenceManager rm = program.getReferenceManager();
		Function f = fm.getFunctionContaining(refToInvalidStr);
		if (f != null) {
			return f;
		}
		
		boolean stop = false;
		for (Address a : rm.getReferenceDestinationIterator(refToInvalidStr, false)) {
			for (Reference r2 : rm.getReferencesTo(a)) {
				if (r2.getReferenceType() == RefType.PARAM) {
					try {
						f = new UndefinedFunction(program, a);
					} catch (IllegalArgumentException e) {
						continue;
					}
					try {
						f = fm.createFunction(null, f.getEntryPoint(), f.getBody(), sourceType());
					} catch (InvalidInputException | OverlappingFunctionException e) {
						// TODO Auto-generated catch block
//						e.printStackTrace();
					}
					stop = true;
					break;
				}
			}
			if (stop) { break; }
		}
		return f;
	}
}
