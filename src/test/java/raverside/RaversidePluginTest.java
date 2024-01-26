package raverside;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.io.IOException;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.junit.Before;
import org.junit.Test;

import raverside.RaversidePlugin.MyProvider;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.UniversalIdGenerator;

public class RaversidePluginTest {

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
    public void setUp() {

	    // Example of initializing a component
	    UniversalIdGenerator.initialize();

        // Initialisation des mocks
        mockTool = mock(PluginTool.class);
        mockProgram = mock(Program.class);
        mockProgramManager = mock(ProgramManager.class);
        mockApiManager = mock(ApiManager.class);
        mockFeatureManager = mock(FeatureManager.class);
        mockHelper = mock(Helper.class);
        mockFunctionComboBox = mock(JComboBox.class);
        mockVariableComboBox = mock(JComboBox.class);
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

        // Initialisation du plugin avec les mocks
        plugin = new RaversidePlugin(mockTool);
        provider = new MyProvider(plugin, "test", mockProgram, mockApiManager, mockFeatureManager, mockHelper);
        
        //For testRefresh
        provider.functionComboBox = mockFunctionComboBox;
        
    }

    //Vérifier que le refresh fonctionne
    @Test
    public void testRefresh() {
    	 provider.refresh();
    	 SwingUtilities.invokeLater(() -> {
    	        verify(mockFunctionComboBox).setModel(any(DefaultComboBoxModel.class));
    	 });
    }
    

    // Vérifiez que le panel est non null et a le bon nombre de composants
    @Test
    public void testBuildPanel() {
        provider.buildPanel();
        assertNotNull(provider.panel);
        assertEquals("Le nombre de composants dans le panel principal doit être 3", 3, provider.panel.getComponentCount());
    }
    
    @Test
    public void testBuildRenameRetypePanel() {
        JPanel panel = provider.buildRenameRetypePanel();

        assertNotNull(panel);
        assertTrue(panel.getLayout() instanceof BorderLayout);
        assertNotNull(panel.getBorder());

        // Vérifier la présence et le type des composants ajoutés
        Component centerComponent = panel.getComponent(0); // basé sur l'ordre d'ajout
        Component southComponent = panel.getComponent(1);

        assertTrue(centerComponent instanceof JPanel); // Vérifier le type de panel
        assertTrue(southComponent instanceof JPanel);
    }
    
    @Test
    public void testBuildComboAndTextFieldPanel() {
        JPanel panel = provider.buildComboAndTextFieldPanel();

        assertNotNull(panel);
        assertTrue(panel.getLayout() instanceof GridLayout);
        assertEquals(3, panel.getComponentCount());

        assertTrue(panel.getComponent(0) instanceof JComboBox);
        assertTrue(panel.getComponent(1) instanceof JComboBox);
        assertTrue(panel.getComponent(2) instanceof JTextField);
    }
    
    @Test
    public void testBuildButtonsPanelRename() {
    	JPanel panel = provider.buildButtonsPanelRename();

        // Vérification de la construction du panel et des boutons
        assertNotNull(panel);
        assertTrue(panel.getLayout() instanceof GridLayout);
        assertEquals(2, panel.getComponentCount());

        JButton renameFunctionsButton = (JButton) panel.getComponent(0);
        assertNotNull(renameFunctionsButton);
        JButton renameVariablesButton = (JButton) panel.getComponent(1);
        assertNotNull(renameVariablesButton);

        // Simuler un clic sur le bouton "Rename Functions"
        renameFunctionsButton.doClick();
        // Vérifier que les interactions attendues se sont produites
        verify(mockFeatureManager).renameFunction("FonctionTest");
        verify(mockConsoleService).addMessage(anyString(), eq("FonctionTest"));
    }
    
    @Test
    public void testBuildOtherPanel() {
        JPanel otherPanel = provider.buildOtherPanel();

        assertNotNull(otherPanel);
        assertTrue(otherPanel.getLayout() instanceof BorderLayout);

        // Vérifiez les types des composants ajoutés
        for (Component comp : otherPanel.getComponents()) {
            if (comp instanceof JComboBox) {
                assertNotNull("JComboBox trouvé", comp);
            } else if (comp instanceof JButton) {
                assertNotNull("JButton trouvé", comp);
            } else if (comp instanceof JPanel) {
                assertNotNull("JPanel trouvé", comp);
            }
        }
    }
    
    @Test
    public void testInitializeComponents() {
        provider.initializeComponents();

        assertNotNull(provider.addCommentsButton);
        assertEquals("Add Comments", provider.addCommentsButton.getText());

        assertNotNull(provider.highlightPatternsButton);
        assertEquals("Highlight Interesting Patterns", provider.highlightPatternsButton.getText());

        assertNotNull(provider.analysePatternsButton);
        assertEquals("Analyze Interesting Patterns", provider.analysePatternsButton.getText());

        assertNotNull(provider.functionComboBoxAnalyze);
        assertEquals(3, provider.functionComboBoxAnalyze.getItemCount());

        assertNotNull(provider.analysisTypeComboBox);
        assertEquals(3, provider.analysisTypeComboBox.getItemCount());
    }
    
    @Test
    public void testSetupListeners() {
        provider.initializeComponents();
        provider.setupListeners();

        assertTrue(provider.addCommentsButton.getActionListeners().length > 0);
        assertTrue(provider.highlightPatternsButton.getActionListeners().length > 0);
        assertTrue(provider.analysePatternsButton.getActionListeners().length > 0);
    }
    
    @Test
    public void testCreateConditionalDropdownPanel() {
        JPanel panel = provider.createConditionalDropdownPanel();

        assertNotNull(panel);

        // Récupérer les composants et vérifier leur type et contenu
        assertEquals(2, panel.getComponentCount());
        assertTrue(panel.getComponent(0) instanceof JComboBox);
        assertTrue(panel.getComponent(1) instanceof JComboBox);

        JComboBox<?> functionSubComboBox = (JComboBox<?>) panel.getComponent(0);
        JComboBox<?> patternSubComboBox = (JComboBox<?>) panel.getComponent(1);

        assertEquals(3, functionSubComboBox.getItemCount());
        assertEquals(3, patternSubComboBox.getItemCount());
    }
    
    /*@Test
    public void testAnalysePatternsAction() throws IOException {
        // Configurez les mocks nécessaires
    	Language mockLanguage = mock(Language.class);
    	when(mockLanguage.supportsPcode()).thenReturn(true);
    	when(mockProgram.getLanguage()).thenReturn(mockLanguage);
        when(mockTool.getService(ProgramManager.class)).thenReturn(mockProgramManager);
        when(mockProgramManager.getCurrentProgram()).thenReturn(mockProgram);
        when(mockFunctionComboBox.getSelectedItem()).thenReturn("All Functions");
        when(mockApiManager.sendAnalysisRequest(any())).thenReturn("responseJson");

        // Exécutez la méthode
        provider.analysePatternsAction(null); // null car l'événement n'est pas utilisé dans la méthode

        // Vérifiez les interactions avec les mocks
        verify(mockApiManager).sendAnalysisRequest(any());
        verify(mockFeatureManager).processAnalysisResponse(eq(mockProgram), eq("responseJson"));
    }*/
    
   
    @Test
    public void testBuildIAPanel() {
        JPanel panel = provider.buildIAPanel();

        assertNotNull(panel);
        assertTrue(panel.getLayout() instanceof BorderLayout);

        // Vérifiez la présence et le type des composants ajoutés
        Component westComponent = panel.getComponent(0); // iaLeftPanel
        Component northComponent = panel.getComponent(1); // buildQuestionArea
        Component centerComponent = panel.getComponent(2); // textScrollPane

        assertTrue(westComponent instanceof JPanel);
        assertTrue(northComponent != null); // buildQuestionArea retourne un Component
        assertTrue(centerComponent instanceof JScrollPane);
    }
    
    @Test
    public void testBuildIALeftPanel() {
        JPanel panel = provider.buildIALeftPanel();

        assertNotNull(panel);
        assertTrue(panel.getLayout() instanceof BorderLayout);

        // Vérifiez la présence et le type des composants ajoutés
        Component southComponent = panel.getComponent(1); // validationButton
        Component centerComponent = panel.getComponent(2); // clearButton

        assertTrue(southComponent instanceof JButton);
        assertTrue(centerComponent instanceof JButton);

        assertEquals("Ask", ((JButton) southComponent).getText());
        assertEquals("Clear", ((JButton) centerComponent).getText());
    }
    
    @Test
    public void testBuildValidationButton() {
        JButton validationButton = provider.buildValidationButton();

        assertNotNull(validationButton);
        assertEquals("Ask", validationButton.getText());
        assertTrue(validationButton.getActionListeners().length > 0);
    }
    
    @Test
    public void testBuildClearButton() {
        JButton clearButton = provider.buildClearButton();

        assertNotNull(clearButton);
        assertEquals("Clear", clearButton.getText());
        assertTrue(clearButton.getActionListeners().length > 0);
    }
    
    @Test
    public void testBuildQuestionArea() {
        JTextArea questionArea = provider.buildQuestionArea();

        assertNotNull(questionArea);
        assertTrue(questionArea.isEditable());
    }

    
}