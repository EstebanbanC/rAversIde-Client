package raverside;

import com.google.gson.JsonElement;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import raverside.RenameDialog.RenameItem;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class FeatureManager {
    private ApiManager apiManager;
    private Program program;
    private PluginTool tool;

    public FeatureManager(ApiManager apiManager, Program program, PluginTool tool) {
        this.apiManager = apiManager;
        this.program = program;
        this.tool = tool;
    }

    public void setProgram(Program program) {
            this.program = program;
        }

    public void renameFunction(String selectedFunctionName) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        try {
            Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
            if (selectedFunction != null) {
                String responseJson = apiManager.sendRenameFunctionRequest(selectedFunctionName);
                processRenameResponse(responseJson, selectedFunction);
            }
        } catch (IOException ex) {
            consoleService.addErrorMessage("API Error", "Error while renaming function: " + ex.getMessage());
        }
    }

    public void renameVariable(String selectedVariableName, String selectedFunctionName) {
        try {
            Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
            Variable selectedVariable = Helper.getVariableByName(selectedVariableName, selectedFunction);
            if (selectedVariable != null) {
                String responseJson = apiManager.sendRenameVariableRequest(selectedVariableName, selectedFunctionName);
                processRenameResponse(responseJson, selectedFunction);
            }
        } catch (IOException ex) {
            Msg.showError(this, null, "API Error", "Error while renaming variable: " + ex.getMessage());
        }
    }

    private void processRenameResponse(String responseJson, Function functionContext) {
        JsonObject response = JsonParser.parseString(responseJson).getAsJsonObject();
        JsonArray renames = response.getAsJsonArray("rename");
        List<RenameItem> itemsToRename = new ArrayList<>();

        if (renames != null) {
            for (int i = 0; i < renames.size(); i++) {
                JsonArray rename = renames.get(i).getAsJsonArray();
                String type = rename.get(0).getAsString();
                String oldName = rename.get(1).getAsString();
                String newName = rename.get(2).getAsString();
                itemsToRename.add(new RenameItem(oldName, newName, type, functionContext));
            }
        }

        RenameDialog renameDialog = new RenameDialog(null, itemsToRename);
        renameDialog.setVisible(true);

        if (renameDialog.isConfirmed()) {
            renameSelected(renameDialog.getSelectedItems());
        }
    }

    private void renameSelected(List<RenameItem> itemsToRename) {
        int transactionID = program.startTransaction("Rename Items");
        try {
            for (RenameItem item : itemsToRename) {
                if ("fonction".equals(item.getItemType())) {
                    Function function = Helper.getFunctionByName(item.getOldName(), program);
                    if (function != null) {
                        function.setName(item.getNewName(), SourceType.USER_DEFINED);
                    }
                } else if ("variable".equals(item.getItemType())) {
                    Variable variable = Helper.getVariableByName(item.getOldName(), item.getFunction());
                    if (variable != null) {
                        variable.setName(item.getNewName(), SourceType.USER_DEFINED);
                    }
                }
            }
        } catch (Exception e) {
            Msg.showError(this, null, "Rename Error", "An error occurred during renaming: " + e.getMessage());
        } finally {
            program.endTransaction(transactionID, true);
        }
    }

    protected void addFunctionCodeToRequest(Function function, Listing listing, DecompInterface decomp, JsonObject code_asm, JsonObject code_c) {
        AddressSetView addrSet = function.getBody();
        InstructionIterator codeUnits = listing.getInstructions(addrSet, true);

        JsonArray functionCode = new JsonArray();
        for (CodeUnit codeUnit : codeUnits) {
            JsonArray line = new JsonArray();
            line.add(codeUnit.getAddress().toString());
            line.add(codeUnit.toString());
            functionCode.add(line);
        }

        code_asm.add(function.getName(), functionCode);

        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        DecompileResults decompRes = decomp.decompileFunction(function, 0, monitor);
        code_c.addProperty(function.getName(), decompRes.getDecompiledFunction().getC());
    }


    protected void processAnalysisResponse(Program program, String responseJson) {
        try {
            JsonObject jsonObject = JsonParser.parseString(responseJson).getAsJsonObject();
            JsonArray jsonArray = jsonObject.getAsJsonArray("comment");

            int maxLineLength = 55;
            int transaction = program.startTransaction("setComments");
            AddressFactory addressFactory = program.getAddressFactory();

            for (JsonElement jsonElement : jsonArray) {
                processComment(jsonElement, program, addressFactory, maxLineLength);
            }

            program.endTransaction(transaction, true);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void processComment(JsonElement jsonElement, Program program, AddressFactory addressFactory, int maxLineLength) {
        JsonArray innerArray = jsonElement.getAsJsonArray();
        try {
            Address address = addressFactory.getAddress(innerArray.get(0).getAsString());
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
            if (codeUnit != null) {
                String comment = innerArray.get(1).getAsString();
                setMultilineComment(codeUnit, comment, maxLineLength);
                Color color = parseColor(innerArray.get(2).getAsString());
                SetColor(codeUnit.getAddress(), color);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private Color parseColor(String colorStr) {
        switch (colorStr.toLowerCase()) {
            case "yellow": case "jaune": return Color.YELLOW;
            case "red": case "rouge": return Color.RED;
            case "orange": return Color.ORANGE;
            default: return Color.GRAY;
        }
    }

    public void SetColor(Address address, Color color) {
        ColorizingService service = tool.getService(ColorizingService.class);
        Color currentColor = service.getBackgroundColor(address);
        if (currentColor != null && currentColor.equals(color))
        {
            int TransactionID = program.startTransaction("UnSetColor");
            service.clearBackgroundColor(address, address);
            program.endTransaction(TransactionID, true);
        }
        else {
            int TransactionID = program.startTransaction("SetColor");
            service.setBackgroundColor(address, address, color);
            program.endTransaction(TransactionID, true);
        }
    }

    protected void setMultilineComment(CodeUnit codeUnit, String comment, int maxLineLength) {
        StringBuilder formattedComment = new StringBuilder();
        String[] words = comment.split(" ");
        StringBuilder line = new StringBuilder();

        for (String word : words) {
            if (line.length() + word.length() > maxLineLength) {
                formattedComment.append(line).append("\n");
                line = new StringBuilder();
            }
            line.append(word).append(" ");
        }

        if (!line.isEmpty()) {
            formattedComment.append(line);
        }

        codeUnit.setComment(CodeUnit.PLATE_COMMENT, formattedComment.toString());
    }

}
