package raverside;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import com.google.gson.JsonObject;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class ApiManager {

    private static final String BASE_URL = "http://127.0.0.1:8000";
    private PluginTool tool;
    private Program program;

    public ApiManager(PluginTool tool, Program program) {
        this.tool = tool;
        this.program = program;
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public String sendRenameFunctionRequest(String selectedFunctionName) throws IOException {
        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        JsonObject request = Helper.createRenameFunctionRequestJson(selectedFunctionName, program, monitor);
        return sendHttpRequest("/renameFunction", request.toString());
    }

    public String sendRenameVariableRequest(String selectedVariableName, String selectedFunctionName) throws IOException {
        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        JsonObject request = Helper.createRenameVariableRequestJson(selectedVariableName, selectedFunctionName, program, monitor);
        return sendHttpRequest("/renameVariable", request.toString());
    }

    public String sendChatBotRequest(String question) throws IOException {
        JsonObject request = Helper.createChatBotRequest(question, program, tool);
        return sendHttpRequest("/handle_chatbot", request.toString());
    }

    public String sendAnalysisRequest(JsonObject request) throws IOException {
        return sendHttpRequest("/analyze", request.toString());
    }

    private String sendHttpRequest(String route, String requestData) throws IOException {
        URL url = new URL(BASE_URL + route);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        try {
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json; utf-8");
            con.setDoOutput(true);

            try (OutputStream os = con.getOutputStream()) {
                byte[] input = requestData.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "utf-8"))) {
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }
            return response.toString();
        } finally {
            con.disconnect();
        }
    }
}
