
//Find Bethesda Settings Variables
//This script will search for data types that follow Bethesda Settings Variables rules and rename them accordingly. Found in Skyrim/Fallout/Starfall.
//These are 4 byte data types followed by 4 bytes of 0 and then a string pointer to the data type.
//@author Alan Tse
//@category Bethesda
//@keybinding
//@menupath Tools.Find Bethesda Settings Variables
//@toolbar
//@license GPL-3.0

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class FindBethesdaVariablesScript extends GhidraScript {

    // Define a mapping of prefixes to data types
    private Map<String, DataType> prefixDataTypeMap = new HashMap<>();

    // Statistics tracking map
    private Map<String, Integer> statisticsMap = new HashMap<>();

    public FindBethesdaVariablesScript() {
        // Initialize the prefix to data type mapping
        prefixDataTypeMap.put("b", BooleanDataType.dataType);
        prefixDataTypeMap.put("c", CharDataType.dataType);
        prefixDataTypeMap.put("s", ShortDataType.dataType);
        prefixDataTypeMap.put("i", IntegerDataType.dataType);
        prefixDataTypeMap.put("l", LongDataType.dataType);
        prefixDataTypeMap.put("f", FloatDataType.dataType);
        prefixDataTypeMap.put("d", DoubleDataType.dataType);
        prefixDataTypeMap.put("str", StringDataType.dataType);
        prefixDataTypeMap.put("byte", ByteDataType.dataType);
        prefixDataTypeMap.put("u", UnsignedIntegerDataType.dataType); // Custom uint32_t mapping
        prefixDataTypeMap.put("ui", UnsignedIntegerDataType.dataType); // Custom uint32_t mapping
        // Initialize statistics map
        for (String prefix : prefixDataTypeMap.keySet()) {
            statisticsMap.put(prefix, 0);
        }
    }

    private boolean interactive = false;

    @Override
    protected void run() throws Exception {
        // Iterate over all labels in the current program
        interactive = askYesNo("Find Bethesda Settings Variables", "Do you want to confirm each variable?");
        boolean overWrite = askYesNo("Find Bethesda Settings Variables", "Overwrite existing entries?");
        boolean getDynamicSymbols = true;

        Listing listing = currentProgram.getListing();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(getDynamicSymbols);

        // Initialize progress tracking
        int totalSymbols = symbolTable.getNumSymbols(); // this appears inaccurate
        int processedSymbols = 0;
        long startTime = System.currentTimeMillis();
        if (getDynamicSymbols) {
            monitor.setIndeterminate(true);
        } else {
            monitor.initialize(totalSymbols);
        }
        long elapsedTime = System.currentTimeMillis() - startTime;
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            Address address = symbol.getAddress();
            String symbolName = symbol.getName();

            // Update the progress
            processedSymbols++;
            elapsedTime = System.currentTimeMillis() - startTime;
            long estimatedTotalTime = (elapsedTime * totalSymbols) / processedSymbols;
            long estimatedTimeRemaining = Math.max(0, (int) (estimatedTotalTime - elapsedTime));
            monitor.checkCanceled();
            monitor.setProgress(processedSymbols);
            monitor.setMessage(
                    String.format("%s: Processing %s %s", formatTime(elapsedTime), symbolName, processedSymbols));

            // Check if the symbol name starts with "DAT_" or a double quotation mark
            if (!overWrite && !symbolName.startsWith("DAT_") && !symbolName.startsWith("\"")) {
                continue; // Skip symbols that don't match the prefix criteria
            }

            // Settings are null 4 bytes later
            if (!isNullBytes(address.add(4)))
                continue;

            Address pointerAddress = address.add(8);
            String stringAtAddress = findStringAtPointer(pointerAddress);
            if (stringAtAddress != null) {
                // Found string pointer
                Data pointerData = listing.getDataAt(pointerAddress);
                if (!pointerData.isPointer()) {
                    DataType stringPointerDataType = new PointerDataType();
                    listing.createData(pointerAddress, stringPointerDataType);
                }
                String newName = stringAtAddress.replaceAll("\\s", "");
                // Extract the prefix
                String prefix = getPrefixForDataType(newName);
                if (prefix != null) {
                    DataType newDataType = prefixDataTypeMap.get(prefix);
                    if (newDataType != null) {
                        Data data = listing.getDataAt(address);
                        DataType oldDataType = null;
                        if (data != null)
                            oldDataType = data.getDataType();
                        // Change data type to match the new name
                        String changestring = address + " (" + oldDataType + " " + symbolName
                                + ") to " + newDataType + " " + newName;
                        println("Checking for rename of symbol at " + changestring);
                        if (!interactive || confirmRename(changestring)) {
                            renameDataAtAddress(address, newName, newDataType);
                            // Increment the count for this data type prefix
                            statisticsMap.put(prefix, statisticsMap.get(prefix) + 1);
                        }
                    }
                }
            }
        }

        // Print statistics
        println(String.format("Processed %s symbols in %s", processedSymbols, formatTime(elapsedTime)));
        printStatistics();
    }

    private boolean isNullBytes(Address address) throws MemoryAccessException {
        // Check that bytes at address are null
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(address);
            if (block != null) {
                // Read the value at the given address
                byte[] value = new byte[4];
                int bytescopied = block.getBytes(address, value);
                if (bytescopied == 4) {
                    for (byte b : value) {
                        if (b != 0) {
                            return false;
                        }
                    }
                    return true;
                }
            }
            return false;
        } catch (MemoryAccessException e) {
            return false;
        }
    }

    // find valid string using hungarian notation
    private String findStringAtPointer(Address address) {
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(address);
            if (block != null) {
                // Read the pointer value at the given address
                Address pointerAddress = getPointerAt(address);
                if (pointerAddress != null && !pointerAddress.equals(Address.NO_ADDRESS)) {
                    // Read the string from the address pointed to by the pointer
                    try {
                        String string = readString(pointerAddress);
                        // Validate the string based on prefixes
                        for (String prefix : prefixDataTypeMap.keySet()) {
                            if (string.startsWith(prefix) && string.length() > prefix.length()
                                    && Character.isUpperCase(string.charAt(prefix.length()))) {
                                return string;
                            }
                        }
                    } catch (NullPointerException e) {
                        e.printStackTrace();
                    }
                }
            }
        } catch (MemoryAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    private Address getPointerAt(Address address) throws MemoryAccessException {
        // Assuming pointers are 4 bytes on a 32-bit system and 8 bytes on a 64-bit
        // system
        int pointerSize = currentProgram.getDefaultPointerSize();
        if (pointerSize == 4) {
            int pointerValue = currentProgram.getMemory().getInt(address);
            if (pointerValue != 0) {
                return address.getNewAddress(pointerValue & 0xFFFFFFFFL);
            }
        } else if (pointerSize == 8) {
            long pointerValue = currentProgram.getMemory().getLong(address);
            if (pointerValue != 0) {
                return address.getNewAddress(pointerValue);
            }
        }
        return null;
    }

    private String readString(Address address) throws MemoryAccessException {
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        if (block != null) {
            byte[] data = new byte[256]; // Read up to 256 bytes for the string
            block.getBytes(address, data);
            return new String(data).split("\0", 2)[0]; // Read until null terminator
        }
        return null;
    }

    private String getPrefixForDataType(String dataTypeName) {
        // Determine prefix based on known prefixes
        for (String prefix : prefixDataTypeMap.keySet()) {
            if (dataTypeName.startsWith(prefix)) {
                return prefix;
            }
        }
        return null;
    }

    private boolean confirmRename(String changeString) throws CancelledException {
        // Show dialog to confirm renaming
        int option = JOptionPane.showOptionDialog(null,
                "Rename " + changeString + "?",
                "Confirm Rename",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                new Object[] { "Rename", "Skip", "Rename All", "Cancel" },
                "Rename");

        switch (option) {
            case JOptionPane.YES_OPTION:
                return true;
            case JOptionPane.NO_OPTION:
                return false;
            case JOptionPane.CANCEL_OPTION: // "Rename All"
                interactive = false;
                return true;
            case 3:
            case JOptionPane.CLOSED_OPTION:
                throw new CancelledException();
            default:
                return false;
        }
    }

    private void renameDataAtAddress(Address address, String newName, DataType newDataType)
            throws CodeUnitInsertionException, InvalidInputException {
        // Rename the data at the specified address and change its type
        Listing listing = currentProgram.getListing();
        Data data = listing.getDataAt(address);
        DataType oldDataType = null;
        String oldName = "";
        if (data != null) {
            oldDataType = data.getDataType();
            oldName = data.getLabel();
        }
        if (listing.isUndefined(address, address.add(4)) || oldDataType.toString().startsWith("undefined")
                || oldName.startsWith("\"")) {
            listing.clearCodeUnits(address, address.add(4), false);
        }
        listing.createData(address, newDataType);
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        symbolTable.createLabel(address, newName, SourceType.ANALYSIS);
        String changestring = address + " (" + oldDataType + " " + oldName
                + ") to " + newDataType + " " + newName;
        println("Renamed data at address " + changestring);
    }

    private void printStatistics() {
        println("Statistics of renamed data types:");
        int total = 0;
        for (Map.Entry<String, Integer> entry : statisticsMap.entrySet()) {
            println("Prefix " + entry.getKey() + " " + prefixDataTypeMap.get(entry.getKey()) + ": " + entry.getValue()
                    + " changes");
            total += entry.getValue();
        }
        println("Total changes:" + total);
    }

    private String formatTime(long milliseconds) {
        long seconds = milliseconds / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        minutes = minutes % 60;
        seconds = seconds % 60;
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }
}
