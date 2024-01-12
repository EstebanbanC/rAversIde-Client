package raverside;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.io.IOException;

public class Helper {

    private static PluginTool tool;
    private Program program;
    private final FeatureManager featureManager;

    public Helper(PluginTool tool, Program program, FeatureManager featureManager) {
        Helper.tool = tool;
        this.program = program;
        this.featureManager = featureManager;
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public static JsonObject createRenameFunctionRequestJson(String functionName, Program program, TaskMonitor monitor) throws IOException {
        Function function = getFunctionByName(functionName, program);
        if (function == null) {
            throw new IOException("Function not found: " + functionName);
        }

        return buildJsonRequest(function, "fonction", functionName, program, monitor);
    }

    public static JsonObject createRenameVariableRequestJson(String variableName, String functionName, Program program, TaskMonitor monitor) throws IOException {
        Function function = getFunctionByName(functionName, program);
        if (function == null) {
            throw new IOException("Function not found: " + functionName);
        }

        Variable variable = getVariableByName(variableName, function);
        if (variable == null) {
            throw new IOException("Variable not found: " + variableName);
        }

        return buildJsonRequest(function, "variable", variableName, program, monitor);
    }



    private static JsonObject buildJsonRequest(Function function, String itemType, String oldName, Program program, TaskMonitor monitor) {
        JsonObject request = new JsonObject();
        JsonArray itemsArray = new JsonArray();
        JsonObject renameItem = new JsonObject();
        renameItem.addProperty("item_type", itemType);
        renameItem.addProperty("old_name", oldName);
        itemsArray.add(renameItem);

        request.add("items", itemsArray);
        addFunctionCodeToJson(request, function, program, monitor);

        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("request :", String.valueOf(request));

        return request;
    }

    private static void addFunctionCodeToJson(JsonObject request, Function function, Program program, TaskMonitor monitor) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        JsonObject code_c = new JsonObject();

        code_c.addProperty(function.getName(), decomp.decompileFunction(function, 0, monitor).getDecompiledFunction().getC());

        request.add("code_c", code_c);
    }

    public static Function getFunctionByName(String functionName, Program program) {
        Listing listing = program.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        for (Function function : functions) {
            if (function.getName().equals(functionName)) {
                return function;
            }
        }
        return null;
    }

    public static Variable getVariableByName(String variableName, Function functionContext) {
        if (functionContext != null) {
            for (Variable variable : functionContext.getAllVariables()) {
                if (variable.getName().equals(variableName)) {
                    return variable;
                }
            }
        }
        return null;
    }

    public static JsonObject createChatBotRequest(String question, Program program, PluginTool tool, JComboBox<String> functionComboBox) {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        
        JsonObject request = new JsonObject();
        request.addProperty("action", "Chatbot");
        request.addProperty("question", question);

        JsonObject code_c = new JsonObject();

        Listing listing = program.getListing();
        FunctionIterator functions = listing.getFunctions(true);

        for (Function function : functions) {
        	if (function.getName().equals(functionComboBox.getSelectedItem())) {
        		code_c.addProperty(function.getName(), decomp.decompileFunction(function, 0, monitor).getDecompiledFunction().getC());
        	}
        }

        request.add("code_c", code_c);
       
        return request;
    }

    protected JsonObject prepareAnalysisRequest(Program program, DecompInterface decomp, boolean getAllCode, JComboBox<String> functionComboBox) {
        JsonObject request = new JsonObject();
        request.addProperty("action", "Analyse");
        request.addProperty("type", "vulnérabilité");

        JsonObject code_asm = new JsonObject();
        JsonObject code_c = new JsonObject();

        Listing listing = program.getListing();
        FunctionIterator functions = listing.getFunctions(true);

        while (functions.hasNext()) {
            Function function = functions.next();
            if (getAllCode || function.getName().equals(functionComboBox.getSelectedItem())) {
                featureManager.addFunctionCodeToRequest(function, listing, decomp, code_asm, code_c);
            }
        }

        request.add("code_asm", code_asm);
        request.add("code_c", code_c);
        return request;
    }

}