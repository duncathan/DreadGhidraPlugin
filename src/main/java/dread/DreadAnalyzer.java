package dread;

import java.util.Arrays;
import java.util.HashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public abstract class DreadAnalyzer extends AbstractAnalyzer {

	protected DreadAnalyzer(String name, String description, AnalyzerType type) {
		super(name, description, type);
	}
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		final String[] md5s = {
				"f5d9aa2af3abef3070791057060ee93c", // 1.0.0
												// TODO: 1.0.1
												// TODO: Demo
				};
		if (!program.getExecutableFormat().equals("Nintendo Switch Binary")) { return false; }
		for (String s : md5s) {
			if (s.equals(program.getExecutableMD5())) {
				return true;
			}
		}
		return false;
	}
	
	protected boolean forceRename = false;
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption("Force renaming", forceRename, null,
				"Rename functions and classes, overwriting user-defined names");
	}
	@Override
	public void optionsChanged(Options options, Program program) {
		forceRename = options.getBoolean("Force renaming", forceRename);
	}
	
	protected SourceType sourceType() {
		return forceRename ? SourceType.USER_DEFINED : SourceType.ANALYSIS;
	}
	
	protected AnalysisPriority priority(int priority) {
		AnalysisPriority p = AnalysisPriority.FUNCTION_ID_ANALYSIS;
		for (int i = 0; i <= priority; i++) {
			p = p.getNext("DREAD"+i);
		}
		return p;
	}
	
	protected Namespace reflection(Program program) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(program.getGlobalNamespace(), "Reflection", SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			return null;
		}
	}
	
	protected Function functionAt(Program program, String addr) {
		return functionAt(program, program.getAddressFactory().getAddress(addr));
	}
	
	protected Function functionAt(Program program, Address addr) {
		return program.getFunctionManager().getFunctionAt(addr);
	}
	
	protected HashMap<String, Function> getRequiredCallees(Program program) {
		HashMap<String, Function> required = new HashMap<String, Function>();
		required.put("__cxa_guard_acquire", functionAt(program, "0x71011f3000"));
		required.put("__cxa_guard_release", functionAt(program, "0x71011f3010"));
		required.put("ReadConfigValue", functionAt(program, "0x71000003d4"));
		required.put("unk1", functionAt(program, "0x7100080124"));
		required.put("unk2", functionAt(program, "0x7100000250"));
		return required;
	}
}
