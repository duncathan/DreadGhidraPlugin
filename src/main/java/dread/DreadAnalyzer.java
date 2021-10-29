package dread;

import java.util.HashMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
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
		return true;
//		final String[] md5s = {
//				"f5d9aa2af3abef3070791057060ee93c", // 1.0.0
//												// TODO: 1.0.1
//												// TODO: Demo
//				};
//		return program.getExecutableFormat() == "Nintendo Switch Binary" && Arrays.asList(md5s).contains(program.getExecutableMD5());
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		//options.registerOption("Option name goes here", false, null,
		//	"Option description goes here");
	}
	
	protected Namespace reflection(Program program) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(program.getGlobalNamespace(), "Reflection", SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			return null;
		}
	}
	
	protected HashMap<String, Function> getRequiredCallees(FunctionManager fm, AddressFactory af) {
		HashMap<String, Function> required = new HashMap<String, Function>();
		required.put("__cxa_guard_acquire", fm.getFunctionAt(af.getAddress("0x71011f3000")));
		required.put("__cxa_guard_release", fm.getFunctionAt(af.getAddress("0x71011f3010")));
		required.put("ReadConfigValue", fm.getFunctionAt(af.getAddress("0x71000003d4")));
		required.put("unk1", fm.getFunctionAt(af.getAddress("0x7100080124")));
		required.put("unk2", fm.getFunctionAt(af.getAddress("0x7100000250")));
		return required;
	}
}