
//Populate parameters based on symbol names. 
//This script will try to populate parameters in a function for 1) class parameters based on namespace detection (e.g., ("class::function") and 2) any parameter definition in the name (e.g., "funcname(param_type1, paramtype_2)()").
//Only valid datatypes within the program will be populated. Any arguments will be renamed with the missing datatype name.
//@author Alan Tse
//@category Functions
//@keybinding
//@menupath Tools.Populate parameters
//@toolbar
//Some initial framework code based on PDBGen https://github.com/wandel/pdbgen, under MIT
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.time.Duration;
import java.time.Instant;
import org.apache.commons.lang3.ArrayUtils;

import javax.management.monitor.Monitor;

import generic.util.Path;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.framework.cmd.Command;

public class PopulateParameters extends GhidraScript {

    boolean debug = false;
    String stopAtFunction = ""; // function to break at; this will turn on debug for that function
    Instant start = Instant.now();
    Instant sectionStart = Instant.now();
    Integer item = 0;
    String lastStatus = "";
    Map<String, Duration> sectionTimer = new LinkedHashMap<String, Duration>();
    List<DataType> datatypes = new ArrayList<DataType>();

    private String timeElapsed() {
        return timeElapsed(start);
    }

    private String timeElapsed(Instant start) {
        Duration duration = Duration.between(start, Instant.now());
        return toString(duration);
    }

    private String toString(Duration duration) {
        long HH = duration.toHours();
        long MM = duration.toMinutesPart();
        long SS = duration.toSecondsPart();
        return String.format("%02d:%02d:%02d", HH, MM, SS);
    }

    private String slugify(String input) {
        return slugify(input, false);
    }

    private String slugify(String input, boolean replacePointer) {
        String result = input;
        String DEFAULT_REPLACE = "_";
        var map = Map.of(
                "&", "*",
                "`", DEFAULT_REPLACE,
                "'", DEFAULT_REPLACE,
                "-", DEFAULT_REPLACE,
                "<", DEFAULT_REPLACE,
                ">", DEFAULT_REPLACE,
                "(", DEFAULT_REPLACE,
                ")", DEFAULT_REPLACE,
                ":", DEFAULT_REPLACE);
        Iterator<Map.Entry<String, String>> itr = map.entrySet().iterator();

        while (itr.hasNext()) {
            Map.Entry<String, String> entry = itr.next();
            result = result.replace(entry.getKey(), entry.getValue());
        }
        if (replacePointer)
            result = result.replace("*", DEFAULT_REPLACE);
        return result;
    }

    private void updateMonitor(String status) throws Exception {
        String itemString = "";
        if (!lastStatus.equals(status)) {
            // we're in a new section
            if (!lastStatus.isEmpty())
                sectionTimer.put(lastStatus, Duration.between(sectionStart, Instant.now()));
            sectionStart = Instant.now();
            lastStatus = status;
        }
        if (monitor.isIndeterminate())
            itemString = item.toString();
        monitor.setMessage(String.format("%s/%s: %s %s", timeElapsed(sectionStart), timeElapsed(), status, itemString));
        monitor.checkCanceled();
        monitor.incrementProgress(1);
        item = item + 1;
    }

    private void printSectionTimers() throws Exception {
        if (!lastStatus.isEmpty())
            sectionTimer.put(lastStatus, Duration.between(sectionStart, Instant.now()));
        Duration total = Duration.between(start, Instant.now());
        String format = "%-40s%s (%,.2f%%)\n";
        printf("Total Time by Section\n");
        for (String s : sectionTimer.keySet()) {
            printf(format, s, toString(sectionTimer.get(s)),
                    (float) sectionTimer.get(s).toSeconds() / total.toSeconds() * 100);
        }
        printf(format, "Total", toString(total), 100.f);
    }

    public List<DataType> getAllDataTypes() throws Exception {
        // this function, despite its name, does not return all datatypes :(
        // we are going to have to go find the missing ones.
        currentProgram.getDataTypeManager().getAllDataTypes(datatypes);
        int total = datatypes.size();
        // for some reason, Ghidra does not include BitField DataTypes in
        // getAllDataTypes, so we manually add them here.
        Iterator<Composite> composites = currentProgram.getDataTypeManager().getAllComposites();
        while (composites.hasNext()) {
            updateMonitor("Getting composites");
            Composite composite = composites.next();
            for (DataTypeComponent component : composite.getComponents()) {
                datatypes.add(component.getDataType());
            }
        }

        // functions are not apart of the data type manager apparently.
        Iterator<Function> functions = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
        total = currentProgram.getFunctionManager().getFunctionCount();
        monitor.initialize(total);
        item = 0;
        while (functions.hasNext()) {
            updateMonitor("Getting functions");
            Function function = functions.next();
            if (function.isThunk())
                continue;
            if (function.isExternal())
                continue;
            FunctionSignature signature = function.getSignature();
            if (signature instanceof FunctionDefinition) {
                datatypes.add((FunctionDefinition) signature);
            }
        }
        return datatypes;
    }

    public void processFunctions() throws Exception {
        Iterator<Function> functions = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
        int total = currentProgram.getFunctionManager().getFunctionCount();
        monitor.initialize(total);
        item = 0;
        while (functions.hasNext()) {
            updateMonitor("Processing functions");
            Function function = functions.next();
            if (function.isThunk())
                continue;
            if (function.isExternal())
                continue;
            if (!stopAtFunction.isEmpty() && function.toString().contains(stopAtFunction)) {
                // Set debug to true since we're stopping at function
                debug = true;
            }
            FunctionSignature signature = function.getSignature();
            if (signature instanceof FunctionDefinition) {
                if (debug && function.toString().contains("::"))
                    printf("Found %s\t with signature %s\n", function, signature);
                function.setCallingConvention​(
                        GenericCallingConvention.getGenericCallingConvention("fastcall").toString());
                int paramIndex = 0;
                boolean modifyParameters = false;
                String className = function.toString().split("::")[0];
                String signatureText = "";
                String functionName = function.toString();
                String[] paramArray = new String[0];
                // handle function declarations in name
                if (functionName.contains("(") && functionName.contains(")")) {
                    int start = functionName.indexOf("(");
                    int end = functionName.indexOf(")");
                    String paramString = functionName.substring(start + 1, end);
                    paramArray = slugify(paramString).split(",", 0);
                    if (paramArray.length == 1 && paramArray[0].equalsIgnoreCase("void"))
                        // our data source assumes the class parameter so void should be a 0 parameter
                        // function e.g. func(void) means no parameters and we treat as func(a_this)
                        paramArray = new String[0];
                    String newFuncName = functionName.substring(0, start);
                    if (debug)
                        printf("\tnewName %s\tparamString %s\tparamArray %s (%s)\n", newFuncName, paramString,
                                Arrays.toString(paramArray),
                                paramArray.length);
                    function.setName(newFuncName, function.getSignatureSource());
                }
                // This is decompile code to potentially look for parameters; however, it is
                // slow. This is disabled because it's probably better to see if we can use a
                // cache and search for registers.
                // DecompInterface ifc = new DecompInterface();
                // ifc.openProgram(currentProgram);
                // String results = ifc.decompileFunction(function, 0, monitor).toString();
                if (function.toString().contains("::")) {
                    paramArray = ArrayUtils.add(paramArray, 0, className + "*");
                    if (debug)
                        printf("\tInserting classname %s\tparamArray %s (%s)\n", className,
                                Arrays.toString(paramArray),
                                paramArray.length);
                }
                ParameterDefinition[] params = signature.getArguments();
                if (debug)
                    printf("Params size %s\n", params.length);
                if (paramIndex == 0 && function.toString().contains("::") || paramArray.length != params.length + 1) {
                    // No parameters, so need to create
                    modifyParameters = true;
                } else if (params.length > 0) {
                    // otherwise check all parameters
                    for (ParameterDefinition param : params) {
                        String newName = null;
                        if (paramIndex < paramArray.length)
                            newName = paramArray[paramIndex++];
                        if (newName != null && !newName.equalsIgnoreCase(param.toString())
                                && param.toString().startsWith("undefined"))
                        // only replace undefined items
                        {
                            modifyParameters = true;
                        }
                    }
                }
                boolean applySignature = false;
                if (modifyParameters && paramArray.length != params.length) {
                    if (paramArray.length > params.length) {
                        if (debug)
                            printf("Resizing params from %s to %s\n", params.length, paramArray.length);
                        params = new ParameterDefinition[paramArray.length];
                    }
                    paramIndex = 0;
                    for (ParameterDefinition param : params) {
                        if (paramArray.length == 0 || paramIndex >= paramArray.length)
                            continue;
                        String newDataType = paramArray[paramIndex];
                        String newName = param != null ? param.getName() : "";
                        DataType newDT = null;
                        if (newDataType.equals("...")) {
                            function.setVarArgs(true);
                            break;
                        } else if (newDataType.endsWith("*")) {
                            newDT = findDataType(newDataType.substring(0, newDataType.length() - 1));
                        } else
                            newDT = findDataType(newDataType);
                        if (param == null && newDT == null) {
                            // create undefined variable
                            newDT = findDataType("undefined8");
                        }
                        if (paramIndex == 0)
                            newName = "this";
                        else if (newDT != null && newDT.toString().startsWith("undefined")
                                && (newName.length() == 0 || newName.startsWith("param"))
                                && !newDataType.equalsIgnoreCase("...")) {
                            // replace default parameter with data type if it exists if still undefined
                            newName = !newDataType.contains("*") ? newDataType
                                    : slugify(newDataType, true);
                        } else
                            // otherwise use index
                            newName = String.valueOf(paramIndex);
                        newName = String.format("a_%s", newName);
                        if (newDT != null) {
                            if (newDataType.endsWith("*"))
                                newDT = new PointerDataType(newDT);
                            if (param == null) {
                                params[paramIndex] = new ParameterDefinitionImpl(newName, newDT, "");
                            } else {
                                param.setDataType(newDT);
                                param.setName(newName);
                            }
                            if (debug)
                                printf("\tSetting param %s/%s to %s (%s) %s\n",
                                        paramIndex,
                                        params.length,
                                        newDT.getName(), newDT.getLength(), newName);
                            applySignature = true;
                        }
                        paramIndex++;
                    }
                    if (applySignature) {
                        for (ParameterDefinition param : params) {
                            if (param == null)
                                continue;
                            signatureText += param + ",";
                        }
                        // strip off final comma
                        signatureText = signatureText.substring(0, signatureText.length() - 1);
                        DataType returnType = signature.getReturnType();
                        String returnTypeText = returnType.toString();
                        if (returnType.toString().startsWith("typedef")) {
                            returnTypeText = returnType.toString().split(" ")[1];
                        }
                        signatureText = String.format("%s %s %s(%s)", returnTypeText,
                                function.getCallingConventionName(), function.getName(),
                                signatureText);
                        DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);
                        if (!stopAtFunction.isEmpty() && function.toString().contains(stopAtFunction)) {
                            if (debug)
                                printf("Applying %s to %s\n", signatureText, function);
                            break;
                        }
                        try {
                            Command cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(),
                                    CParserUtils.parseSignature(service, currentProgram, signatureText),
                                    SourceType.USER_DEFINED);
                            boolean run = cmd.applyTo(currentProgram);
                            printf("Applied %s to %s\n", signatureText, function);
                        } catch (Exception e) {
                            printf("Error applying %s to %s:\t%s\n", signatureText, function, e);
                            break;
                        }

                    }

                }
            }
        }

    }

    private DataType findDataType(String dataType) {
        DataType best = null;
        for (DataType dt : datatypes) {
            if (dt.getName().toString().equals(dataType)) {
                // if (debug)
                // printf("\tFound dt %s\t%s\n", dt.getDisplayName(), dt.getLength());
                if (best == null) {
                    // if (debug)
                    // printf("\tReplacing null with %s (%s)\n",
                    // dt.getDisplayName(), dt.getLength());
                    best = dt;
                } else if (best != null && best.getLength() < dt.getLength()) {
                    // if (debug)
                    // printf("\tReplacing %s (%s) with %s (%s)\n", best.getDisplayName(),
                    // best.getLength(),
                    // dt.getDisplayName(), dt.getLength());
                    best = dt;
                }
            }
        }
        if (debug)
            if (best == null)
                printf("\tNo result for %s\n", dataType);
            else
                printf("\tReturning %s (%s) for %s\n", best.getDisplayName(),
                        best.getLength(),
                        dataType);
        return best;
    }

    public void run() throws Exception {
        if (state.getTool() != null) {
            ConsoleService console = state.getTool().getService(ConsoleService.class);
            console.clearMessages();
        }

        getAllDataTypes();
        processFunctions();
        printSectionTimers();
        return;
    }
}