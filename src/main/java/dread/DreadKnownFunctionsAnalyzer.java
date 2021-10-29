/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dread;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class DreadKnownFunctionsAnalyzer extends DreadAnalyzer {

	public DreadKnownFunctionsAnalyzer() {
		super("(Dread) Identify Known Functions", "Performs analysis on specific known functions such as CRC64", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		FunctionManager fm = program.getFunctionManager();
		AddressFactory af = program.getAddressFactory();
		
		try {
			Function crc64 = fm.getFunctionAt(af.getAddress("0x7100001570"));
			if (crc64 != null) {
				crc64.setName("CRC64", SourceType.ANALYSIS);
			}
			return true;
		} catch (DuplicateNameException | InvalidInputException e) {
			e.printStackTrace();
			return false;
		}
	}
}

