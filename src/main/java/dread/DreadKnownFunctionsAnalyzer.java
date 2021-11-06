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

import java.util.Map.Entry;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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
		setPriority(priority(0));
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		for (Entry<String, Function> entry : knownFunctions(program).entrySet()) {
			Function f = entry.getValue();
			String name = entry.getKey();
			if (name.startsWith("FUN_")) { continue; }
			try {
				f.setName(entry.getKey(), sourceType());
				f.setParentNamespace(program.getGlobalNamespace());
				f.setCallingConvention(f.getDefaultCallingConventionName());
			} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				e.printStackTrace();
				return false;
			}
		}
		return true;
	}
}

