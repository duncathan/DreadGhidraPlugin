package dread;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.python.google.common.collect.Lists;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
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
		SymbolTable st = program.getSymbolTable();
		Listing listing = program.getListing();
		
		Namespace reflection = reflection(program);
		if (reflection == null) { return false; }
		
		HashMap<String, Function> requiredCallees = getRequiredCallees(program);
		
		Pattern divideNamespaces = Pattern.compile("\\w+(?:<.*>)?(?:\\s*(?:const|\\*))*");
		
		int count = 0;
		for (@SuppressWarnings("unused") Function f : fm.getFunctions(set, true)) {
			count++;
		}
		
		monitor.setProgress(0);
		monitor.setIndeterminate(false);
		monitor.setMessage("Creating functions in .init_array...");
		if (!parseInitArray(program, set, monitor, log)) { return false; }
		
		monitor.setProgress(0);
		monitor.setMaximum(count);
		monitor.setIndeterminate(false);
		monitor.setMessage("Checking functions for reflection classes...");
		for (Function f : fm.getFunctions(set, true)) {
			if (monitor.isCancelled()) { return false; }
			monitor.incrementProgress(1);
			if (!forceReanalysis && f.getParentNamespace() != program.getGlobalNamespace()) { continue; }
			
			if (identifyStandardInit(program, f, divideNamespaces, set)) { continue; }
			if (identifyOtherInit(program, f, divideNamespaces, set)) { continue; }
		}
		return true;
	}
	
	public boolean createInit(Program program, Function f, Pattern p, String fullName, String initName, String extraTag) {
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
			f.setName(initName, sourceType());
			f.addTag("REFLECTION");
			if (extraTag != null) {
				f.addTag(extraTag);
			}
		} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public String findName(Program program, Address addr, AddressSetView set) {
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
		ss.search(new AddressSet(addr, set.getMaxAddress()), callback, false, stringMonitor);
		return nameBuilder.toString().trim();
	}
	
	public boolean identifyStandardInit(Program program, Function f, Pattern p, AddressSetView set) {
		// must be a function with no arguments
		if (f.getParameterCount() > 0) { return false; }
		
		// ensure the function calls all the relevant functions used by the initializers
		Set<Function> called = f.getCalledFunctions(null);
		HashMap<String, Function> requiredCallees = getRequiredCallees(program);
		if (!called.containsAll(requiredCallees.values()) || requiredCallees.values().containsAll(called)) { return false; }
		
		ArrayList<FuncWithParams> rcvCalls = callsWithParams(program, f);
		rcvCalls.removeIf(fn -> fn.function() != requiredCallees.get("ReadConfigValue"));
		
		if (rcvCalls.size() == 0 || rcvCalls.get(0).params().size() == 0) { return false; }
		
		Address classNameAddr = rcvCalls.get(0).params().get(0).getToAddress();
		
		String fullName = findName(program, classNameAddr, set);
		
		// ensure a class name could be found
		if (fullName.length() == 0) { 
			return false; 
		}
		
		return createInit(program, f, p, fullName, "init", null);
	}
	
	public boolean identifyOtherInit(Program program, Function f, Pattern p, AddressSetView set) {
		HashMap<String, Function> knownFuncs = getRequiredCallees(program);
		ArrayList<FuncWithParams> allCalls = callsWithParams(program, f);
		if (
			allCalls.size() < 4 ||
			allCalls.get(0).function() != knownFuncs.get("ReadConfigValue") ||
			allCalls.get(1).function() != knownFuncs.get("UNK_250") ||
			allCalls.get(2).function() != knownFuncs.get("ReadConfigValue") ||
			allCalls.get(3).function() != knownFuncs.get("UNK_250")
		) { return false; }
		ArrayList<FuncWithParams> rcvCalls = new ArrayList<FuncWithParams>(allCalls);
		rcvCalls.removeIf(c -> c.function() != knownFuncs.get("ReadConfigValue"));
		if (rcvCalls.size() <= 2) { return false; }
		FuncWithParams lastRcv = null;
		for (FuncWithParams rcv : Lists.reverse(rcvCalls)) {
			if (allCalls.size() == allCalls.indexOf(lastRcv) ||
				knownFuncs.get("UNK_250") == allCalls.get(allCalls.indexOf(lastRcv)+1).function()) {
				continue;
			}
			
			if (rcv.params().size() == 0) { continue; }
			Address classNameAddr = rcv.params().get(0).getToAddress();
			String name = findName(program, classNameAddr, set);
			if (name.contains("::")) {
				lastRcv = rcv;
				break;
			}
		}
		
		if (lastRcv == null) { return false; }
		
		Address classNameAddr = lastRcv.params().get(0).getToAddress();
		String fullName = findName(program, classNameAddr, set);
		
		if (fullName.length() == 0 || fullName.equals("sources") || fullName.equals("binaries")) { return false; }
		
		if (fullName.contains("<")) {
			return createInit(program, f, p, fullName, "initTemplate", "TEMPLATE_INIT");
		} else if (fullName.contains("::E") || fullName.contains("::S")) {
			return createInit(program, f, p, fullName, "initEnums", "ENUM_INIT");
		}
		
		return createInit(program, f, p, fullName, "initOther", "OTHER_INIT");
	}
	
	public boolean parseInitArray(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		ReferenceManager rm = program.getReferenceManager();
		Listing listing = program.getListing();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!block.getName().equals(".init_array")) { continue; }
			monitor.setMaximum(block.getSize()/8);
			for (int i = 0; i < block.getSize(); i += 8) {
				if (monitor.isCancelled()) { return false; }
				monitor.incrementProgress(1);
				Address a = block.getStart().add(i);
				Reference[] r = rm.getReferencesFrom(a);
				if (r.length == 0) {
					try {
						listing.createData(a, new PointerDataType());
					} catch (CodeUnitInsertionException | DataTypeConflictException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					r = rm.getReferencesFrom(a);
				}
				findOrCreateFuncAt(program, r[0].getToAddress());
			}
			return true;
		}
		return false;
	}
}
