package raverside;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.UniversalIdGenerator;

import static org.mockito.Mockito.*;

import java.io.IOException;

import javax.swing.JComboBox;

public class FeatureManagerTest {
    private RaversidePlugin plugin;
    private RaversidePlugin.MyProvider provider;
    private PluginTool mockTool;
    private Program mockProgram;
    private ProgramManager mockProgramManager;
    private ApiManager mockApiManager;
    private FeatureManager mockFeatureManager;
    private Helper mockHelper;
    private JComboBox<String> mockFunctionComboBox;
    private JComboBox<String> mockVariableComboBox;
    private Listing mockListing;
    private FunctionIterator mockFunctionIterator;
    private Function mockFunction;
    private ConsoleService mockConsoleService;


    @Before
    public void setup() {
	    // Example of initializing a component
	    UniversalIdGenerator.initialize();

        // Initialisation des mocks
        mockTool = mock(PluginTool.class);
        mockProgram = mock(Program.class);
        mockProgramManager = mock(ProgramManager.class);
        mockApiManager = mock(ApiManager.class);
        mockFeatureManager = mock(FeatureManager.class);
        mockHelper = mock(Helper.class);
        mockListing = mock(Listing.class);
        mockFunctionIterator = mock(FunctionIterator.class);
        mockFunction = mock(Function.class);
        mockConsoleService = mock(ConsoleService.class);
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getListing()).thenReturn(mockListing);
        when(mockListing.getFunctions(true)).thenReturn(mockFunctionIterator);
        when(mockFunctionIterator.hasNext()).thenReturn(true, false); // Simulez au moins une fonction
        when(mockFunctionIterator.next()).thenReturn(mockFunction);
        when(mockFunction.getName()).thenReturn("TestFunction");
        when(mockTool.getService(ConsoleService.class)).thenReturn(mockConsoleService);
        when(mockFunctionComboBox.getSelectedItem()).thenReturn("FonctionTest");
        when(mockVariableComboBox.getSelectedItem()).thenReturn("VariableTest");
        mockFeatureManager = new FeatureManager(mockApiManager, mockProgram, mockTool);
    }

    @Test
    public void testRenameFunction() throws IOException {
        // Setup your test
        String selectedFunctionName = "TestFunction";

        // Call the method you want to test
        mockFeatureManager.renameFunction(selectedFunctionName);

        // Verify the results (this is just an example, you'll need to adapt this to your needs)
        verify(mockApiManager).sendRenameFunctionRequest(selectedFunctionName);
    }
}