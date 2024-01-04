/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package raverside;

import java.awt.*;

import javax.swing.*;

import com.google.gson.JsonObject;

import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Arrays;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;
import resources.ResourceManager;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
		status = PluginStatus.STABLE,
		packageName = ExamplesPluginPackage.NAME,
		category = PluginCategoryNames.EXAMPLES,
		shortDescription = "Plugin short description goes here.",
		description = "Plugin long description goes here."
		)
//@formatter:on
public class RaversidePlugin extends ProgramPlugin {

	MyProvider provider;
	Program program;
	private ApiManager apiManager;
	private FeatureManager featureManager;
	private Helper helper;
	
	


	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public RaversidePlugin(PluginTool tool) {
		super(tool);
		this.apiManager = new ApiManager(tool, program);
	    this.featureManager = new FeatureManager(apiManager, program, tool);
		this.helper = new Helper(tool, program, featureManager);


	    // TODO: Customize provider (or remove if a provider is not desired)
	    String pluginName = getName();
	    provider = new MyProvider(this, pluginName, this.getCurrentProgram(), apiManager, featureManager, helper);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}
	
	

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

	@Override
	protected void programActivated(Program p) {
		program = p;
		provider.setProgram(p);
	}

	// TODO: If provider is desired, it is recommended to move it to its own file
	protected static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private JPanel renameRetypePanel;
		private JPanel otherPanel;
		private JPanel IAPanel;
		private DockingAction action;
		private DockingAction actionGetFunctions;

		protected JComboBox<String> functionComboBox;
		private JComboBox<String> functionComboBoxAnalyze;
		private JComboBox<String> variableComboBox;
		private JComboBox<String> analysisTypeComboBox;
		private JComboBox<String> functionSubComboBox;
		private JComboBox<String> patternSubComboBox;
		private JTextField inputTextField;
		private JTextArea textArea;
		private JTextArea questionArea;
		private JButton addCommentsButton;
		private JButton highlightPatternsButton;
		private JButton analysePatternsButton;

		// Services et gestionnaires
		private ApiManager apiManager;
		private FeatureManager featureManager;
		private Helper helper;
		private Program program;
		private PluginTool tool;
		

		public MyProvider(Plugin plugin, String owner, Program program, ApiManager apiManager, FeatureManager featureManager, Helper helper) {
			super(plugin.getTool(), owner, owner);
			this.apiManager = apiManager;
			this.featureManager = featureManager;
			this.helper = helper;
			setIcon(ResourceManager.loadImage("images/Icone.png"));
			setProgram(program);
			tool = plugin.getTool();
			buildPanel();
			createActions();
			refresh();
		}

		public void setProgram(Program p) {
		    program = p;
		    featureManager.setProgram(p);
		    apiManager.setProgram(p);
			helper.setProgram(p);
		}

		private void refresh() {
			ProgramManager programManager = tool.getService(ProgramManager.class);

			if (programManager != null) {

				Program currentProgram = programManager.getCurrentProgram();

				if (currentProgram != null) {
					Listing listing = currentProgram.getListing();
					FunctionIterator functions = listing.getFunctions(true);

					ArrayList<String> functionNames = new ArrayList<>();
					while (functions.hasNext()) {
						Function function = functions.next();
						if (isFunctionPartOfExecutable(function)) {
							functionNames.add(function.getName());
						}
					}

					Collections.sort(functionNames);
					functionNames.add(0, "All Functions");

					SwingUtilities.invokeLater(new Runnable() {
						@Override
						public void run() {
							functionComboBox.setModel(new DefaultComboBoxModel<>(functionNames.toArray(new String[0])));
							functionSubComboBox.setModel(new DefaultComboBoxModel<>(functionNames.toArray(new String[0])));
							functionComboBoxAnalyze.setModel(new DefaultComboBoxModel<>(functionNames.toArray(new String[0])));
						}
					});
				}
			}
		}
		
		private void buildPanel() {
			textArea = new JTextArea();
			textArea.setEditable(false);
		    panel = new JPanel(new GridLayout(3, 1));
		    panel.add(buildRenameRetypePanel());
		    panel.add(buildOtherPanel());
		    panel.add(buildIAPanel());
		    setVisible(true);
		}

		private JPanel buildRenameRetypePanel() {
			renameRetypePanel = new JPanel(new BorderLayout());
			renameRetypePanel.setBorder(BorderFactory.createTitledBorder("Rename/Retype"));

			renameRetypePanel.add(buildComboAndTextFieldPanel(), BorderLayout.CENTER);
			renameRetypePanel.add(buildButtonsPanelRename(), BorderLayout.SOUTH);

			return renameRetypePanel;
		}
		private JPanel buildComboAndTextFieldPanel() {
		    JPanel comboAndTextFieldPanel = new JPanel(new GridLayout(3, 1));
		    functionComboBox = new JComboBox<>(new String[]{"Please refresh"});
		    variableComboBox = new JComboBox<>(new String[]{"Please refresh"});
		    inputTextField = new JTextField();
		    
		    comboAndTextFieldPanel.add(functionComboBox);
		    comboAndTextFieldPanel.add(variableComboBox);
		    comboAndTextFieldPanel.add(inputTextField);

		    return comboAndTextFieldPanel;
		}

		private JPanel buildButtonsPanelRename() {
			JPanel buttonsPanelRename = new JPanel(new GridLayout(1, 2));

			JButton renameFunctionsButton = new JButton("Rename Functions");
			renameFunctionsButton.addActionListener(e -> {
				String selectedFunctionName = (String) functionComboBox.getSelectedItem();
				ConsoleService consoleService = tool.getService(ConsoleService.class);
				consoleService.addMessage("Function name :", selectedFunctionName);
				featureManager.renameFunction(selectedFunctionName);
				refresh();
			});

			JButton renameVariablesButton = new JButton("Rename Variables");
			renameVariablesButton.addActionListener(e -> {
				String selectedVariableName = (String) variableComboBox.getSelectedItem();
				String selectedFunctionName = (String) functionComboBox.getSelectedItem();
				featureManager.renameVariable(selectedVariableName, selectedFunctionName);
				refresh();
			});

			buttonsPanelRename.add(renameFunctionsButton);
			buttonsPanelRename.add(renameVariablesButton);

			return buttonsPanelRename;
		}

		private JPanel buildOtherPanel() {
			otherPanel = new JPanel(new BorderLayout());
			otherPanel.setBorder(BorderFactory.createTitledBorder("Analyse"));

			initializeComponents();
			setupListeners();

			JPanel conditionalDropdownPanel = createConditionalDropdownPanel();

			otherPanel.add(BorderLayout.NORTH, analysisTypeComboBox);
			otherPanel.add(BorderLayout.WEST, addCommentsButton);
			otherPanel.add(BorderLayout.CENTER, highlightPatternsButton);
			otherPanel.add(BorderLayout.SOUTH, analysePatternsButton);
			otherPanel.add(BorderLayout.EAST, conditionalDropdownPanel);

			return otherPanel;
		}

		private void initializeComponents() {
			addCommentsButton = new JButton("Add Comments");
			highlightPatternsButton = new JButton("Highlight Interesting Patterns");
			analysePatternsButton = new JButton("Analyze Interesting Patterns");
			functionComboBoxAnalyze = new JComboBox<>(new String[]{"Function 1", "Function 2", "Function 3"});
			analysisTypeComboBox = new JComboBox<>(new String[]{"Vulnerabilities", "Functions", "Patterns"});
		}

		private void setupListeners() {
			addCommentsButton.addActionListener(this::addCommentsAction);
			highlightPatternsButton.addActionListener(this::highlightPatternsAction);
			analysePatternsButton.addActionListener(this::analysePatternsAction);
		}

		private JPanel createConditionalDropdownPanel() {
			JPanel conditionalDropdownPanel = new JPanel();
			functionSubComboBox = new JComboBox<>(new String[]{"Function A", "Function B", "Function C"});
			patternSubComboBox = new JComboBox<>(new String[]{"Pattern 1", "Pattern 2", "Pattern 3"});

			conditionalDropdownPanel.add(functionSubComboBox);
			conditionalDropdownPanel.add(patternSubComboBox);

			return conditionalDropdownPanel;
		}


		private void analysePatternsAction(ActionEvent e) {
			ProgramManager programManager = tool.getService(ProgramManager.class);
			Program currentProgram = programManager.getCurrentProgram();
			boolean getAllCode = "All Functions".equals(functionComboBox.getSelectedItem());
			DecompInterface decomp = new DecompInterface();
			decomp.openProgram(currentProgram);

			JsonObject request = helper.prepareAnalysisRequest(currentProgram, decomp, getAllCode, functionComboBox);

			try {
				String responseJson = apiManager.sendAnalysisRequest(request);
				if (responseJson != null) {
					featureManager.processAnalysisResponse(currentProgram, responseJson);
				}
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}



		private JPanel buildIAPanel() {
			IAPanel = new JPanel(new BorderLayout());
			IAPanel.setBorder(BorderFactory.createTitledBorder("IA"));

			JPanel iaLeftPanel = buildIALeftPanel();
			JScrollPane textScrollPane = new JScrollPane(textArea);

			IAPanel.add(BorderLayout.WEST, iaLeftPanel);
			IAPanel.add(BorderLayout.NORTH, buildQuestionArea());
			IAPanel.add(BorderLayout.CENTER, textScrollPane);

			return IAPanel;
		}

		private JPanel buildIALeftPanel() {
			JPanel iaLeftPanel = new JPanel(new BorderLayout());
			iaLeftPanel.add(BorderLayout.NORTH, new JLabel("Ask questions to our ChatBot:"));

			JButton validationButton = buildValidationButton();
			JButton clearButton = buildClearButton();

			iaLeftPanel.add(BorderLayout.SOUTH, validationButton);
			iaLeftPanel.add(BorderLayout.CENTER, clearButton);

			return iaLeftPanel;
		}

		private JButton buildValidationButton() {
			JButton validation = new JButton("Ask");
			validation.addActionListener(e -> {
				String question = questionArea.getText();
                try {
                    String response = apiManager.sendChatBotRequest(question);
					textArea.append("Response from API:\n" + response + "\n");
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            });
			return validation;
		}

		private JButton buildClearButton() {
			JButton clear = new JButton("Clear");
			clear.addActionListener(e -> textArea.setText(""));
			return clear;
		}

		private JTextArea buildQuestionArea() {
			questionArea = new JTextArea();
			questionArea.setEditable(true);
			return questionArea;
		}


		// NE SAIT PAS SI ON GARDE

		private void addCommentsAction(ActionEvent e) {
			try {
				ProgramManager programManager = tool.getService(ProgramManager.class);
				Program currentProgram = programManager.getCurrentProgram();

				GoToService goToService = tool.getService(GoToService.class);
				ProgramLocation currentLocation = goToService.getDefaultNavigatable().getLocation();
				Address addressComment = currentLocation.getAddress();

				URL url = new URL("https://raversideapi.anthonyvolpelliere.com/comments/" + addressComment.toString());
				BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
				StringBuilder response = new StringBuilder();
				String inputLine;
				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine + "\n");
				}
				in.close();

				Listing listing = currentProgram.getListing();
				int Transaction = program.startTransaction("setComments");
				CodeUnit codeUnit = listing.getCodeUnitAt( addressComment );
				codeUnit.setComment(CodeUnit.PLATE_COMMENT, "AddCommentToScript - This is an added comment!\nResponse from URL:\n" + response.toString());
				program.endTransaction(Transaction, true);
				Msg.info(this, "Des commentaires pertinents ont bien été rajoutés");
			} catch (MalformedURLException e2) {
				// Handle the exception (e.g., print an error message)
				e2.printStackTrace();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}

		private void highlightPatternsAction(ActionEvent e) {
			Msg.info(getClass(), "Des parties interessantes ont bien été surlignées");

			GoToService goToService = tool.getService(GoToService.class);
			ProgramLocation currentLocation = goToService.getDefaultNavigatable().getLocation();
			Address addressColor = currentLocation.getAddress();
			featureManager.SetColor(addressColor, Color.GREEN);
		}


	

		// TODO: Customize actions
		private void createActions() {


			actionGetFunctions = new DockingAction("Refresh", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					refresh();
				}
			};
			actionGetFunctions.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			actionGetFunctions.setEnabled(true);
			actionGetFunctions.markHelpUnnecessary();
			dockingTool.addLocalAction(this, actionGetFunctions);

//			DockingAction action = new DockingAction("getAsm", getName()) {
//				@Override
//				public void actionPerformed(ActionContext context) {
//					ProgramManager programManager = tool.getService(ProgramManager.class);
//					Program currentProgram = programManager.getCurrentProgram();
//					boolean getAllCode = false; // Flag to indicate if we want all code
//
//					// Check if "All Functions" is selected
//					if (functionComboBox.getSelectedItem().equals("All Functions")) {
//						getAllCode = true;
//					}
//
//					JsonObject request = new JsonObject();
//					JsonObject code_asm = new JsonObject();
//					JsonArray line;
//
//					request.addProperty("context", "monContexte");
//					request.addProperty("action", "Analyse");
//					request.addProperty("type", "vulnérabilité");
//
//					Listing listing = currentProgram.getListing();
//					FunctionIterator functions = listing.getFunctions(true);
//
//					while (functions.hasNext()) {
//						Function function = functions.next();
//
//						// Check if we want all code or if this is the selected function
//						if (getAllCode || function.getName().equals(functionComboBox.getSelectedItem())) {
//							AddressSetView addrSet = function.getBody();
//							InstructionIterator codeUnits = listing.getInstructions(addrSet, true);
//
//							// Add the function's code to the code_asm JsonObject
//							JsonArray functionCode = new JsonArray();
//							while (codeUnits.hasNext()) {
//								CodeUnit codeUnit = codeUnits.next();
//								line = new JsonArray();
//								line.add(codeUnit.getAddress().toString());
//								line.add(codeUnit.toString());
//								functionCode.add(line);
//							}
//
//							code_asm.add(function.getName(), functionCode);
//						}
//					}
//
//					request.add("code_asm", code_asm);
//					textArea.append(request.toString() + "\n");
//				}
//			};
//
//			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
//			action.setEnabled(true);
//			action.markHelpUnnecessary();
//			dockingTool.addLocalAction(this, action);
//
//			action = new DockingAction("getC", getName()) {
//				@Override
//				public void actionPerformed(ActionContext context) {
//
//					ProgramManager programManager = tool.getService(ProgramManager.class);
//					Program currentProgram = programManager.getCurrentProgram();
//					DecompInterface decomp = new DecompInterface();
//					decomp.openProgram(currentProgram);
//					Listing listing = currentProgram.getListing();
//					Function selectedFunction = null; // Function variable for the selected function
//					boolean getAllCode = false; // Flag to indicate if we want all code
//
//					// Check if "All Functions" is selected
//					if (functionComboBox.getSelectedItem().equals("All Functions")) {
//						getAllCode = true;
//					} else {
//						// Obtain the selected function
//						String selectedFunctionName = (String) functionComboBox.getSelectedItem();
//						selectedFunction = getFunctionByName(selectedFunctionName);
//					}
//
//					TaskMonitor monitor = tool.getService(ConsoleTaskMonitor.class);
//
//					JsonObject request = new JsonObject();
//					JsonObject allFunc = new JsonObject();
//
//					request.addProperty("context", "monContexte");
//					request.addProperty("action", "Analyse");
//					request.addProperty("type", "vulnérabilité");
//
//					FunctionIterator functions = listing.getFunctions(true);
//
//					while (functions.hasNext()) {
//						Function function = functions.next();
//
//						// Check if we want all code or if this is the selected function
//						if (getAllCode || function.equals(selectedFunction)) {
//							DecompileResults decompRes = decomp.decompileFunction(function, 0, monitor);
//							allFunc.addProperty(function.getName(), decompRes.getDecompiledFunction().getC());
//						}
//					}
//					request.add("codeC", allFunc);
//					textArea.append(request.toString());
//
//				}
//			};
//
//			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
//			action.setEnabled(true);
//			action.markHelpUnnecessary();
//			dockingTool.addLocalAction(this, action);



			functionComboBox.addItemListener(new ItemListener() {
				@Override
				public void itemStateChanged(ItemEvent e) {
					if (e.getStateChange() == ItemEvent.SELECTED) {                        
						String selectedFunctionName = (String) functionComboBox.getSelectedItem();
						Function selectedFunction = Helper.getFunctionByName(selectedFunctionName, program);

						if (selectedFunction != null) {
							// Récupérer les variables de la fonction sélectionnée
							Variable[] variables = selectedFunction.getAllVariables();

							// Transform the array of Variable objects into an array of their names as strings
							String[] variableNames = Arrays.stream(variables)
									.map(Variable::getName) 
									.toArray(String[]::new);


							variableComboBox.setModel(new DefaultComboBoxModel<>(variableNames));
						}
					}
				}
			});

		}

		public boolean isFunctionPartOfExecutable(Function function) {
			ProgramManager programManager = tool.getService(ProgramManager.class);
			Program currentProgram = programManager.getCurrentProgram();

			Symbol functionSymbol = function.getSymbol();
			if (functionSymbol == null || functionSymbol.isExternal()) {
				return false;
			}

			// Liste des fonctions à exclure
			List<String> excludedFunctions = Arrays.asList(
					"_init", "_start", "_fini", "frame_dummy", 
					"mainCRTStartup", "__libc_csu_init", "__libc_csu_fini", "_exit",
					"__do_global_dtors_aux", "deregister_tm_clones", "register_tm_clones"
					);

			// Obtenez le nom de la fonction et vérifiez si elle est dans la liste des exclusions
			String functionName = function.getName();
			if (excludedFunctions.contains(functionName)) {
				return false;
			}

			// Vérifiez si la fonction appartient à un espace de noms qui indique qu'elle est importée ou générée par Ghidra
			Namespace functionNamespace = functionSymbol.getParentNamespace();
			if (functionNamespace != null && (functionNamespace.isExternal() || functionNamespace.getName().equals("Imports"))) {
				return false;
			}

			// Analyse des instructions de la fonction
			InstructionIterator it = currentProgram.getListing().getInstructions(function.getBody(), true);
			if (it.hasNext()) {
				Instruction firstInstr = it.next();
				String firstMnemonic = firstInstr.getMnemonicString();

				// Vérifiez la séquence d'instructions
				if ((firstMnemonic.equals("PUSH") || firstMnemonic.equals("ENDBR64")) && it.hasNext()) {
					Instruction secondInstr = it.next();
					if ("JMP".equals(secondInstr.getMnemonicString()) || "RET".equals(secondInstr.getMnemonicString()) && !it.hasNext()) {
						return false;  // Exclure si la séquence correspond à PUSH/JMP ou ENDBR64/JMP ou ENDBR64/RET avec seulement deux instructions
					}
				}
			}

			return true; // Inclure la fonction si aucune des conditions d'exclusion n'est remplie
		}



		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}