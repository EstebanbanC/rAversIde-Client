package raverside;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

import java.net.URI;
import java.util.concurrent.CountDownLatch;
import java.util.function.Consumer;

public class MyWebSocketClient extends WebSocketClient  {
	private Consumer<String> messageConsumer;
    private PluginTool tool;
    
    public MyWebSocketClient(PluginTool tool, URI serverUri, Consumer<String> messageConsumer) {
        super(serverUri);
        this.messageConsumer = messageConsumer;
        this.tool = tool;
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("opened connection", "ok");
    }

    @Override
    public void onMessage(String message) {
        if (messageConsumer != null) {
            messageConsumer.accept(message);
	        ConsoleService consoleService = tool.getService(ConsoleService.class);
	        consoleService.addMessage("Received", "ok");
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        ConsoleService consoleService = tool.getService(ConsoleService.class);
        consoleService.addMessage("Closed connection", "ok");
    }

    @Override
    public void onError(Exception ex) {
        ex.printStackTrace();
    }
    
}
