package dread;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DreadInitArrayAnalyzer extends DreadAnalyzer {

	public DreadInitArrayAnalyzer() {
		super("(Dread) Initialize functions", "Ensures that every function in .init_array is initialized as an actual function.", AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(priority(0));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.setProgress(0);
		monitor.setIndeterminate(false);
		monitor.setMessage("Creating functions in .init_array...");
		
		ReferenceManager rm = program.getReferenceManager();
		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		SymbolTable st = program.getSymbolTable();
		
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
				Address entry = r[0].getToAddress();
				if (listing.getInstructionAt(entry) == null) {
					new DisassembleCommand(entry, null, true).applyTo(program);
					findOrCreateFuncAt(program, entry);
				} else {
					if (forceReanalysis) {
						Function f = functionAt(program, entry);
						if (f != null) {
							f.getSymbol().delete();
							fm.removeFunction(entry);
						}
					}
					findOrCreateFuncAt(program, entry);
				}
			}
			return true;
		}
		return false;
	}
}
