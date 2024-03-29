package raverside;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import com.google.gson.JsonObject;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

import javax.swing.JComboBox;
import javax.swing.JTextArea;

public class ApiManager {

    private static final String BASE_URL = "https://raverside.aymeric-daniel.com";
    private PluginTool tool;
    private Program program;
    private static MyWebSocketClient client;

    private JTextArea theTextArea;
    private final ExecutorService executorService = Executors.newFixedThreadPool(4);
    private final ReentrantLock lock = new ReentrantLock();

    public ApiManager(PluginTool tool, Program program) {
        this.tool = tool;
        this.program = program;
    }
    
    private void handleWebSocketResponse(String message) {

        theTextArea = RaversidePlugin.MyProvider.textArea;
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("", message);
        if (message.endsWith("FIN")) {
            client.close(0);
            return; 
        }
		theTextArea.append(message);
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public void sendRenameFunctionRequest(String selectedFunctionName, Consumer<String> callback, Consumer<Exception> errorCallback) throws IOException {
        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        JsonObject request = Helper.createRenameFunctionRequestJson(selectedFunctionName, program, monitor);

        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("a request is in progress  :", "renameFunction");
        sendHttpRequestAsync("/renameFunction", request.toString(), callback);
    }

    public void sendRenameVariableRequest(String selectedVariableName, String selectedFunctionName, Consumer<String> callback, Consumer<Exception> errorCallback) throws IOException {
        TaskMonitor monitor = tool.getService(TaskMonitor.class);
        JsonObject request = Helper.createRenameVariableRequestJson(selectedVariableName, selectedFunctionName, program, monitor);
        
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("a request is in progress  :", "renameVariable");
        sendHttpRequestAsync("/renameVariable", request.toString(), callback);
    }

    public void sendChatBotRequest(String question, Consumer<String> callback, JComboBox<String> functionComboBox) throws URISyntaxException {

        URI serverUri = new URI("ws://127.0.0.1:8080");
        Consumer<String> wsResponseConsumer = this::handleWebSocketResponse;
        client = new MyWebSocketClient(tool, serverUri, wsResponseConsumer);
        client.connect();
        JsonObject request = Helper.createChatBotRequest(question, program, tool, functionComboBox);


        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("a request is in progress  :", "ChatBot " + request);
        sendHttpRequestAsync("/handle_chatbot", request.toString(), callback);

        consoleService.addMessage("message sent :", "OK");
    }

    public void sendAnalysisRequest(JsonObject request, Consumer<String> callback) {

        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("a request is in progress  :", "Analysis");
        sendHttpRequestAsync("/analyze", request.toString(), callback);
    }
    
    private void sendHttpRequestAsync(String route, String requestData, Consumer<String> callback) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        executorService.submit(() -> {
            try {
                String response = sendHttpRequest(route, requestData);
                callback.accept(response);
            } catch (IOException e) {
                e.printStackTrace();
                consoleService.addErrorMessage("Thread error", "Error submitting task: " + e.getMessage());
            } 
        });
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
    
    // Méthode pour fermer le pool de threads lors de la fermeture de l'application
    public void shutdown() {
        executorService.shutdown();
    }
}