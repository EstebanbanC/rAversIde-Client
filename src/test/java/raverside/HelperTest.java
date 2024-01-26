package raverside;

import org.junit.Before;
import org.junit.Test;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;
import com.google.gson.JsonObject;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;

public class HelperTest {
    private Program mockProgram;
    private Function mockFunction;
    private TaskMonitor mockMonitor;
    private Listing mockListing;
    private FunctionIterator mockFunctionIterator;
    private PluginTool mockTool;
    private ProgramManager mockProgramManager;
    @Before
    public void setUp() {

        mockTool = mock(PluginTool.class);
        mockProgramManager = mock(ProgramManager.class);
        mockProgram = mock(Program.class);
        mockFunction = mock(Function.class);
        mockMonitor = mock(TaskMonitor.class);
        mockListing = mock(Listing.class);
        mockFunctionIterator = mock(FunctionIterator.class);
        
     // Configurez le mock de Program pour retourner un mock de Listing
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockProgram.getListing()).thenReturn(mockListing);
        // Si nécessaire, configurez également le mock de Listing pour retourner des fonctions
        // Par exemple, pour simuler la méthode getFunctions
        when(mockFunctionIterator.hasNext()).thenReturn(true, false); // Pour simuler au moins une fonction
        when(mockFunctionIterator.next()).thenReturn(mockFunction);
        when(mockListing.getFunctions(true)).thenReturn(mockFunctionIterator);
    }
}
