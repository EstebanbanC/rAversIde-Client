package raverside;

import com.google.gson.JsonElement;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import org.python.antlr.ast.Str;
import raverside.RaversidePlugin.MyProvider;
import raverside.RenameDialog.RenameItem;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.awt.*;
import java.io.Console;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.management.monitor.Monitor;
import javax.swing.Icon;
import javax.swing.ImageIcon;

import static org.python.modules.time.Time.sleep;

public class FeatureManager {
    private ApiManager apiManager;
    private Program program;
    private PluginTool tool;
    private RaversidePlugin raversidePlugin;

    public FeatureManager(ApiManager apiManager, Program program, PluginTool tool, RaversidePlugin raversidePlugin) {
        this.apiManager = apiManager;
        this.program = program;
        this.tool = tool;
        this.raversidePlugin = raversidePlugin;
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public void renameFunction(String selectedFunctionName) throws IOException {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
        if (selectedFunction != null) {
            apiManager.sendRenameFunctionRequest(selectedFunctionName, responseJson -> {
                if (responseJson != null) {
                    processRenameResponse(responseJson, selectedFunction);
                    consoleService.addMessage("response :", String.valueOf(responseJson) + "\n");
                }
            }, error -> {
                consoleService.addErrorMessage("API Error", "Error while renaming function: " + error.getMessage());
            });
        }
    }

    public void renameVariable(String selectedVariableName, String selectedFunctionName) throws IOException {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);
        Variable selectedVariable = Helper.getVariableByName(selectedVariableName, selectedFunction);
        if (selectedVariable != null) {
            apiManager.sendRenameVariableRequest(selectedVariableName, selectedFunctionName, responseJson -> {
                if (responseJson != null) {
                    processRenameResponse(responseJson, selectedFunction);
                    consoleService.addMessage("response :", String.valueOf(responseJson) + "\n");
                }
            }, error -> {
                consoleService.addErrorMessage("API Error", "Error while renaming variable: " + error.getMessage());
            });
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
            raversidePlugin.getProvider().refresh();
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
                setColor(codeUnit.getAddress(), color);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private Color parseColor(String colorStr) {
        return switch (colorStr.toLowerCase()) {
            case "yellow", "jaune" -> Color.YELLOW;
            case "red", "rouge" -> Color.RED;
            case "orange" -> Color.ORANGE;
            default -> Color.GRAY;
        };
    }

    public void setColor(Address address, Color color) {
        ColorizingService service = tool.getService(ColorizingService.class);
        Color currentColor = service.getBackgroundColor(address);
        if (currentColor != null && currentColor.equals(color)) {
            int TransactionID = program.startTransaction("UnSetColor");
            service.clearBackgroundColor(address, address);
            program.endTransaction(TransactionID, true);
        } else {
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

    public void highlightAndCommentListingFromDecompiledString(String _functionName, String _line, String _comment, Color _color) {
        if (_functionName == null || _functionName.isEmpty()) {
            throw new IllegalArgumentException("Function name cannot be null or empty");
        }
        if (_line == null || _line.isEmpty()) {
            throw new IllegalArgumentException("Line cannot be null or empty");
        }
        if (_comment == null) {
            throw new IllegalArgumentException("Comment cannot be null");
        }
        if (_color == null) {
            throw new IllegalArgumentException("Color cannot be null");
        }

        ConsoleService consoleService = tool.getService(ConsoleService.class);
        try {
            if (program == null) {
                throw new Exception("No current program");
            }

            Function function = getFunctionByName(_functionName);
            if (function == null) {
                throw new Exception("No function found");
            }
            consoleService.addMessage("Function found ", function.getName() + "\n");


            ClangTokenGroup tokenGroup = getDecompiledTokens(function);
            if (tokenGroup == null) {
                throw new Exception("No token group found");
            }
            consoleService.addMessage("Token group found ", tokenGroup.toString() + "\n");


            ArrayList<Address> address = getDecompiledAddressFromLine(tokenGroup, _line, 0);
            if (address == null) {
                throw new Exception("No address found");
            }
            consoleService.addMessage("Address found ", address.toString() + "\n");
            setColorOnMultipleAddresses(address, _color);


            Listing listing = program.getListing();
            if (listing == null) {
                throw new Exception("No listing found");
            }
            listing.setComment(address.get(0), CodeUnit.PLATE_COMMENT, _comment);


        } catch (Exception e) {
            consoleService.addErrorMessage("Error", e.getMessage());
        }
    }

    private Function getFunctionByName(String _functionName) {
        if (program == null) {
            Msg.error(this, "No current program");
            return null;
        }
        FunctionIterator functionIterator = program.getListing().getFunctions(true);
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            if (function.getName().equals(_functionName)) {
                return function;
            }
        }
        return null;
    }

    private ClangTokenGroup getDecompiledTokens(Function _function) {
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(program);
        DecompileResults decompResults = decompInterface.decompileFunction(_function, 60, null);
        if (decompResults != null) {
            return decompResults.getCCodeMarkup();
        }
        return null;
    }


    private ArrayList<Address> getDecompiledAddressFromLine(ClangNode _node, String _line, int _index) {
        if (_node == null || _line == null || _line.isEmpty()) {
            throw new IllegalArgumentException("Node and line cannot be null or empty");
        }
        if (!_node.toString().contains(_line))
            return null;

//        ConsoleService consoleService = tool.getService(ConsoleService.class);

        int numChildren = _node.numChildren();

        for (int i = 0; i < numChildren; i++) {
            ClangNode child = _node.Child(i);
            if (!child.toString().contains(_line)) {
                continue;
            }
//            consoleService.addMessage("", "\t".repeat(_index) + child + "\n");
            ArrayList<Address> address = getDecompiledAddressFromLine(child, _line, _index + 1);
            if (address == null) {
                continue;
            }
            return address;

        }
        String tmp = "";
        ArrayList<Address> ret = new ArrayList<>();
        for (int i = 0; i < numChildren; i++) {
            ClangNode child = _node.Child(i);
            if (child.toString().isEmpty() || child.toString().equals(" ")) {
                continue;
            }
            if (_line.contains(child.toString())) {
                tmp = tmp.concat(child.toString());
                Address childMinAddress = child.getMinAddress();
                Address childMaxAddress = child.getMaxAddress();
                if (childMinAddress != null && childMaxAddress != null) {
                    ret.add(childMinAddress);
                    ret.add(childMaxAddress);
                }
                if (tmp.equals(_line)) {
                    break;
                }
            }
        }
        if (!tmp.isEmpty()) {
            return ret;
        }

        return null;
    }

    public void setColorOnMultipleAddresses(ArrayList<Address> _addresses, Color _color) {
        if (_addresses == null) {
            throw new IllegalArgumentException("Addresses cannot be null");
        }
        if (_color == null) {
            throw new IllegalArgumentException("Color cannot be null");
        }

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");

        for (int i = 0; i < _addresses.size(); i += 2) {
            Address start = _addresses.get(i);
            Address end = _addresses.get(i + 1);
            service.setBackgroundColor(start, end, _color);
        }
        program.endTransaction(TransactionID, true);
    }

}