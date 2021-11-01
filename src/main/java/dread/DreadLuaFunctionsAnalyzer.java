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

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class DreadLuaFunctionsAnalyzer extends DreadAnalyzer {

	public DreadLuaFunctionsAnalyzer() {
		super("(Dread) Identify Lua Functions", "Performs analysis on functions exported to Lua", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(priority(0));
	}
	
	protected Namespace getGameLuaNamespace(Program program) {
		try {
			return program.getSymbolTable().getOrCreateNameSpace(program.getGlobalNamespace(), "GameLua", SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			return null;
		}
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Listing listing = program.getListing();
		ReferenceManager rm = program.getReferenceManager();
		DataTypeManager dtm = program.getDataTypeManager();
		DataType longType = dtm.getDataType("/longlong");
		
		DataTypePath luaStatePath = new DataTypePath("/Lua", "lua_State");
		DataType luaState = dtm.getDataType(luaStatePath);
		if (luaState == null) {
			luaState = new StructureDataType("lua_State", 184, dtm);
			try {
				luaState.setCategoryPath(luaStatePath.getCategoryPath());
				dtm.addDataType(luaState, null);
			} catch (DuplicateNameException e) {
				e.printStackTrace();
			}
		}
		
		FunctionSignature luaCFunction = (FunctionSignature) dtm.getDataType(new DataTypePath("/Lua", "lua_CFunction"));
		if (luaCFunction == null) {
			FunctionDefinitionDataType cfunctionType = new FunctionDefinitionDataType(new CategoryPath("/Lua"), "lua_CFunction", dtm);
			cfunctionType.setReturnType(longType);
			cfunctionType.setArguments(new ParameterDefinition[] {
					new ParameterDefinitionImpl("L", PointerDataType.getPointer(luaState, dtm), null),
			});
	
			dtm.addDataType(cfunctionType, null);
			luaCFunction = cfunctionType;
		}
		
		Namespace gameLua = getGameLuaNamespace(program);
		if (gameLua == null) {
			return false;
		}
		
		Address gameLRegStart =  program.getAddressFactory().getAddress("0x7101c55240");
		for (int i = 0; i < 617; ++i) {
			Address stringPtrAddress = gameLRegStart.add(i * 16);
			Address funcPtrAddress = gameLRegStart.add(i * 16 + 8);
			
			Address stringAddress = rm.getReferencesFrom(stringPtrAddress)[0].getToAddress();
			Data it = listing.getDataAt(stringAddress);
			if (it == null || !it.getDataType().toString().equals("string") ) {
				continue;
			}
			String name = (String) it.getValue();
			
			Address funcAddress = rm.getReferencesFrom(funcPtrAddress)[0].getToAddress();
			Function f = functionAt(program, funcAddress);
			if (f == null) {
				f = new UndefinedFunction(program, funcAddress);
				try {
					f = program.getFunctionManager().createFunction(name, gameLua, funcAddress, f.getBody(), SourceType.ANALYSIS);
				} catch (InvalidInputException | OverlappingFunctionException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else {
				try {
					f.setParentNamespace(gameLua);
					f.setName(name, SourceType.ANALYSIS);
				} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
					e.printStackTrace();
				}
			}
			
			new ApplyFunctionSignatureCmd(
					funcAddress,
					luaCFunction,
					SourceType.ANALYSIS
			).applyTo(program);
		}
		
		return true;
	}
}

