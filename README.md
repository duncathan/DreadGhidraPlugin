# Ghidra Dread Plugin

A suite of analyzers to assist in reverse engineering Metroid Dread.

## Dependencies

Requires [https://github.com/Adubbz/Ghidra-Switch-Loader/](Ghidra-Switch-Loader) to be installed. 

## Installation

 - Start Ghidra and use the "Install Extensions" dialog (`File -> Install Extensions...`).
 - Press the + button in the upper right corner.
 - Select the zip file in the file browser, then restart Ghidra.

## Usage

### Initial run
 1) For your initial run, load a project with `exefs/main`. Do not analyze immediately, if prompted.
 2) Open the Auto Analysis menu (`Analysis -> Auto Analysis`) and select the default options. Make the following changes:
    - Enable `Aggressive Instruction Finder`
    - Enable `Decompiler Parameter ID`
    - Disable `Non-Returning Functions - Discovered`
 3) Analyze!

### Subsequent analysis
Select the desired analyzer from the `Analysis -> One-Shot` dropdown and analyze.
