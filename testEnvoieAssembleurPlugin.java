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
package testenvoieassembleur;

import java.awt.*;

import javax.swing.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import resources.ResourceManager;
import testenvoieassembleur.RenameDialog.*;

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
public class testEnvoieAssembleurPlugin extends ProgramPlugin {

	MyProvider provider;
	Program program;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public testEnvoieAssembleurPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName, this.getCurrentProgram());

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
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private JPanel renameRetypePanel;
		private JPanel otherPanel;
		private JPanel IAPanel;
		private JPanel iaLeftPanel;
		private JPanel conditionalDropdownPanel;

		private DockingAction action;
		private DockingAction actionGetFunctions;

		private JComboBox<String> functionComboBox;
		private JComboBox<String> functionComboBoxAnalyze;
		private JComboBox<String> variableComboBox;
		private JComboBox<String> analysisTypeComboBox;
		private JComboBox<String> functionSubComboBox;
		private JComboBox<String> patternSubComboBox;
		private JTextField inputTextField;
		private JTextArea textArea;
		private JTextArea questionArea;
		private JScrollPane textScrollPane;

		private JButton rename;
		private JButton renameAllButton;
		private JButton retypeAllButton;
		private JButton addCommentsButton;
		private JButton highlightPatternsButton;
		private JButton analysePatternsButton;
		private JButton validation;
		private JButton clear;

		public static Program program;
		public static PluginTool tool;

		public MyProvider(Plugin plugin, String owner, Program program) {
			super(plugin.getTool(), owner, owner);
			setIcon(ResourceManager.loadImage("images/Icone.png"));
			setProgram(program);
			tool = plugin.getTool();
			buildPanel();
			createActions();
		}

		public void setProgram(Program p) {
			program = p;
		}

		// Customize GUI
		private void buildPanel() {

			panel = new JPanel(new GridLayout(3, 1));

			// Premier bloc
			renameRetypePanel = new JPanel(new BorderLayout());
			renameRetypePanel.setBorder(BorderFactory.createTitledBorder("Rename/Retype"));

			// Créez un panel pour les ComboBox et le TextField
			JPanel comboAndTextFieldPanel = new JPanel(new GridLayout(3, 1));
			functionComboBox = new JComboBox<>(new String[]{"Function 1", "Function 2", "Function 3"});
			variableComboBox = new JComboBox<>(new String[]{"Variable 1", "Variable 2", "Variable 3"});
			inputTextField = new JTextField();
			comboAndTextFieldPanel.add(functionComboBox);
			comboAndTextFieldPanel.add(variableComboBox);
			comboAndTextFieldPanel.add(inputTextField);
			renameRetypePanel.add(comboAndTextFieldPanel, BorderLayout.CENTER);  // Ajoutez ce panel au centre

			// Créez un panel pour les boutons
			JPanel buttonsPanelRename = new JPanel(new GridLayout(1, 2));  // Un panel avec un GridLayout pour les boutons
			JButton renameFunctionsButton = new JButton("Rename Functions");
			JButton renameVariablesButton = new JButton("Rename Variables");
			buttonsPanelRename.add(renameFunctionsButton);
			buttonsPanelRename.add(renameVariablesButton);
			renameRetypePanel.add(buttonsPanelRename, BorderLayout.SOUTH);  // Ajoutez ce panel en bas

			// Deuxième bloc
			otherPanel = new JPanel(new BorderLayout());
			otherPanel.setBorder(BorderFactory.createTitledBorder("Analyse"));

			addCommentsButton = new JButton("Add Comments");
			highlightPatternsButton = new JButton("Highlight Interesting Patterns");
			analysePatternsButton = new JButton("Analyze Interesting Patterns");
			functionComboBoxAnalyze = new JComboBox<>(new String[]{"Function 1", "Function 2", "Function 3"});
			analysisTypeComboBox = new JComboBox<>(new String[]{"Vulnerabilities", "Functions", "Patterns"});

			otherPanel.add(BorderLayout.NORTH, analysisTypeComboBox);
			otherPanel.add(BorderLayout.WEST, addCommentsButton);
			otherPanel.add(BorderLayout.CENTER, highlightPatternsButton);
			otherPanel.add(BorderLayout.SOUTH, analysePatternsButton);

			// Panel pour les menus déroulants conditionnels
			conditionalDropdownPanel = new JPanel();
			otherPanel.add(BorderLayout.EAST, conditionalDropdownPanel);

			// Menu déroulant conditionnel pour Analysis 1
			functionSubComboBox = new JComboBox<>(new String[]{"Function A", "Function B", "Function C"});
			functionSubComboBox.setVisible(false);
			conditionalDropdownPanel.add(functionSubComboBox);

			// Menu déroulant conditionnel pour Analysis 2
			patternSubComboBox = new JComboBox<>(new String[]{"Pattern 1", "Pattern 2", "Pattern 3"});
			patternSubComboBox.setVisible(false);
			conditionalDropdownPanel.add(patternSubComboBox);

			analysisTypeComboBox.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					JComboBox<?> source = (JComboBox<?>) e.getSource();
					functionSubComboBox.setVisible(source.getSelectedIndex() == 1);
					patternSubComboBox.setVisible(source.getSelectedIndex() == 2);
				}
			});

			// Troisième bloc
			IAPanel = new JPanel(new BorderLayout());
			IAPanel.setBorder(BorderFactory.createTitledBorder("IA"));

			iaLeftPanel = new JPanel(new BorderLayout());
			iaLeftPanel.add(BorderLayout.NORTH,new JLabel("Ask questions to our ChatBot:"));

			textArea = new JTextArea();
			textArea.setEditable(false);
			textScrollPane = new JScrollPane(textArea);

			questionArea = new JTextArea();
			questionArea.setEditable(true);

			validation = new JButton("Ask");
			clear = new JButton("Clear");
			iaLeftPanel.add(BorderLayout.SOUTH, validation);
			iaLeftPanel.add(BorderLayout.CENTER, clear);


			IAPanel.add(BorderLayout.WEST, iaLeftPanel);
			IAPanel.add(BorderLayout.NORTH, questionArea);
			IAPanel.add(BorderLayout.CENTER, textScrollPane);

			// Ajout des blocs au panel principal
			panel.add(renameRetypePanel);
			panel.add(otherPanel);
			panel.add(IAPanel);

			setVisible(true);

			renameFunctionsButton.addActionListener(new ActionListener() {
			    @Override
			    public void actionPerformed(ActionEvent e) {
			        // Obtenez le nom de la fonction sélectionnée et le code assembleur
			        String selectedFunctionName = (String) functionComboBox.getSelectedItem();
			        Function selectedFunction = getFunctionByName(selectedFunctionName);
			        String asmCode = getAsmCode(selectedFunction); // Implémentez cette méthode pour obtenir le code assembleur

			        JsonObject request = new JsonObject();
			        JsonArray itemsArray = new JsonArray();

			        JsonObject renameItem = new JsonObject();
			        renameItem.addProperty("item_type", "fonction");
			        renameItem.addProperty("old_name", selectedFunctionName);
			        itemsArray.add(renameItem);

			        request.add("items", itemsArray);
			        request.addProperty("code_asm", asmCode);

			        try {
			            String responseJson = sendApiRequest("/renameFunction", request);
			            textArea.append(responseJson.toString() + "\n");
			            JsonObject response = JsonParser.parseString(responseJson).getAsJsonObject();

			            JsonArray renames = response.getAsJsonArray("rename");
			            List<RenameItem> itemsToRename = new ArrayList<>();
			            if (renames != null) {
			                for (int i = 0; i < renames.size(); i++) {
			                    JsonArray rename = renames.get(i).getAsJsonArray();
			                    String type = rename.get(0).getAsString();
			                    String oldName = rename.get(1).getAsString();
			                    String newName = rename.get(2).getAsString();
			                    itemsToRename.add(new RenameItem(oldName, newName));
			                }
			            }

			            RenameDialog renameDialog = new RenameDialog(null, itemsToRename);
			            renameDialog.setVisible(true);

			            if (renameDialog.isConfirmed()) {
			                List<RenameItem> selectedItems = renameDialog.getSelectedItems();
			                renameSelectedFunctions(selectedItems);
			            }
			        } catch (IOException ex) {
			            // Gérer les exceptions ici
			        }
			    }
			});

			renameVariablesButton.addActionListener(new ActionListener() {
			    @Override
			    public void actionPerformed(ActionEvent e) {
			        // Obtenez le nom de la variable sélectionnée
			        String selectedVariableName = (String) variableComboBox.getSelectedItem();
			        Variable selectedVariable = getVariableByName(selectedVariableName);
			        if (selectedVariable != null) {
			            // Implémentez cette méthode pour obtenir le code assembleur lié à la variable
			            String asmCode = getAsmCode(selectedVariable.getFunction()); 

			            JsonObject request = new JsonObject();
			            JsonArray itemsArray = new JsonArray();

			            JsonObject renameItem = new JsonObject();
			            renameItem.addProperty("item_type", "variable");
			            renameItem.addProperty("old_name", selectedVariableName);
			            itemsArray.add(renameItem);

			            request.add("items", itemsArray);
			            request.addProperty("code_asm", asmCode);

			            try {
			                String responseJson = sendApiRequest("/renameVariable", request);
			                JsonObject response = JsonParser.parseString(responseJson).getAsJsonObject();

			                JsonArray renames = response.getAsJsonArray("rename");
			                List<RenameItem> itemsToRename = new ArrayList<>();
			                if (renames != null) {
			                    for (int i = 0; i < renames.size(); i++) {
			                        JsonArray rename = renames.get(i).getAsJsonArray();
			                        String type = rename.get(0).getAsString();
			                        String oldName = rename.get(1).getAsString();
			                        String newName = rename.get(2).getAsString();
			                        itemsToRename.add(new RenameItem(oldName, newName));
			                    }
			                }

			                RenameDialog renameDialog = new RenameDialog(null, itemsToRename);
			                renameDialog.setVisible(true);

			                if (renameDialog.isConfirmed()) {
			                    List<RenameItem> selectedItems = renameDialog.getSelectedItems();
			                    renameSelectedVariables(selectedItems);
			                }
			            } catch (IOException ex) {
			                // Gérer les exceptions ici
			                Msg.info(this, "Erreur lors de la communication avec l'API : " + ex.getMessage());
			            }
			        } else {
			            // Informez l'utilisateur si la variable sélectionnée n'a pas été trouvée
			            Msg.info(this, "La variable sélectionnée n'a pas été trouvée.");
			        }
			    }
			});


			//renameAllButton.addActionListener(new ActionListener() {
			//    @Override
			//    public void actionPerformed(ActionEvent e) {
			//        // Ajoutez votre code ici
			//        Msg.info(this, "Toutes les variables ont bien été renommées");
			//    }
			//});

			//retypeAllButton.addActionListener(new ActionListener() {
			//    @Override
			//    public void actionPerformed(ActionEvent e) {
			//        // Ajoutez votre code ici
			//       Msg.info(this, "Tous les types non définis ont bien été corrigés");
			//    }
			//});

			addCommentsButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					// Ajoutez votre code ici

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
			});

			highlightPatternsButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					// Ajoutez votre code ici
					Msg.info(getClass(), "Des parties interessantes ont bien été surlignées");

					GoToService goToService = tool.getService(GoToService.class);
					ProgramLocation currentLocation = goToService.getDefaultNavigatable().getLocation();
					Address addressColor = currentLocation.getAddress();
					SetColor(addressColor, Color.GREEN);

				}
			});

			analysePatternsButton.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					ProgramManager programManager = tool.getService(ProgramManager.class);
					Program currentProgram = programManager.getCurrentProgram();
					boolean getAllCode = false; // Flag to indicate if we want all code

					// Check if "Tout le code" is selected
					if (functionComboBox.getSelectedItem().equals("Tout le code")) {
						getAllCode = true;
					}

					JsonObject request = new JsonObject();
					JsonObject code_asm = new JsonObject();
					JsonArray line;

					request.addProperty("context", "monContexte");
					request.addProperty("action", "Analyse");
					request.addProperty("type", "vulnérabilité");

					Listing listing = currentProgram.getListing();
					FunctionIterator functions = listing.getFunctions(true);

					while (functions.hasNext()) {
						Function function = functions.next();

						if (getAllCode || function.getName().equals(functionComboBox.getSelectedItem())) {
							AddressSetView addrSet = function.getBody();
							InstructionIterator codeUnits = listing.getInstructions(addrSet, true);

							JsonArray functionCode = new JsonArray();
							while (codeUnits.hasNext()) {
								CodeUnit codeUnit = codeUnits.next();
								line = new JsonArray();
								line.add(codeUnit.getAddress().toString());
								line.add(codeUnit.toString());
								functionCode.add(line);
							}

							code_asm.add(function.getName(), functionCode);
						}
					}

					request.add("code_asm", code_asm);
					textArea.append(request.toString() + "\n");

					// Envoi de la requête POST
					String requestJson = request.toString();
					try {
					    URL url = new URL("http://127.0.0.1:8000/analyze");
					    HttpURLConnection con = (HttpURLConnection) url.openConnection();
					    con.setRequestMethod("POST");
					    con.setRequestProperty("Content-Type", "application/json; utf-8");
					    con.setRequestProperty("Accept", "application/json");
					    con.setDoOutput(true);

					    try(OutputStream os = con.getOutputStream()) {
					        byte[] input = requestJson.getBytes("utf-8");
					        os.write(input, 0, input.length);           
					    }

					    StringBuilder response = new StringBuilder();
					    try(BufferedReader br = new BufferedReader(
					            new InputStreamReader(con.getInputStream(), "utf-8"))) {
					        String responseLine = null;
					        while ((responseLine = br.readLine()) != null) {
					            response.append(responseLine.trim());
					        }
					    }
					    
					    // Afficher la réponse pour le débogage
					    textArea.append("Response from API:\n" + response.toString() + "\n");

					    // Utilisation de la réponse
					    //String jsonString = response.toString();
					    try {
					        String jsonString = response.toString();
					    	//String jsonString = "{\"comment\":[[\"00101216\",\"Potential vulnerability: buffer overflow. The SUB instruction decreases the stack pointer by 0x38, which creates space for local variables. If the function writes more than 0x38 bytes to the stack, it can overwrite the return address and potentially execute arbitrary code.\",\"red\"],[\"0010127f\",\"Potential vulnerability: null pointer dereference. The JZ instruction jumps to 0x001012b2 if the byte located at [RBP - 0x11] is zero. If the value at [RBP - 0x11] is uninitialized or is not properly checked before this point, it can result in a null pointer dereference.\",\"red\"]]}";
							  
					        
					        // Débogage : Imprimez la réponse JSON
					        System.out.println("JSON Response: " + jsonString);

					        JsonObject jsonObject = JsonParser.parseString(jsonString).getAsJsonObject();
					        JsonArray jsonArray = jsonObject.getAsJsonArray("comment");

					        int maxLineLength = 55; // Définissez la longueur maximale de ligne souhaitée

				            int transaction = currentProgram.startTransaction("setComments");
				            AddressFactory addressFactory = currentProgram.getAddressFactory();
				            Address address;
				            Color color;

					        for (JsonElement jsonElement : jsonArray) {
					            JsonArray innerArray = jsonElement.getAsJsonArray();

					            try {
					                address = addressFactory.getAddress(innerArray.get(0).getAsString());
					                CodeUnit codeUnit = listing.getCodeUnitAt(address);
					                if (codeUnit != null) {
					                	setMultilineComment(codeUnit, innerArray.get(1).getAsString(), maxLineLength);
					                    String colorStr = innerArray.get(2).getAsString();

					                    switch (colorStr) {
					                        case "yellow": color = Color.YELLOW; break;
					                        case "jaune": color = Color.YELLOW; break;
					                        case "red": color = Color.RED; break;
					                        case "rouge": color = Color.RED; break;
					                        case "orange": color = Color.ORANGE; break;
					                        default: color = Color.GRAY; break;
					                    }
					                    SetColor(codeUnit.getAddress(), color);
					                }
					            } catch (Exception exception) {
					                exception.printStackTrace();
					            }
					        }
					        currentProgram.endTransaction(transaction, true);

					    } catch (Exception exception) {
					        exception.printStackTrace();
					    }
					}
					catch (Exception exception) {
				        exception.printStackTrace();
				    }

				}
			});



			validation.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					Msg.info(this, "Requête envoyée a l'IA");
						ProgramManager programManager = tool.getService(ProgramManager.class);
						Program currentProgram = programManager.getCurrentProgram();
						boolean getAllCode = false; // Flag to indicate if we want all code

						// Check if "Tout le code" is selected
						if (functionComboBox.getSelectedItem().equals("Tout le code")) {
							getAllCode = true;
						}

						JsonObject request = new JsonObject();
						JsonObject code_asm = new JsonObject();
						JsonArray line;

						request.addProperty("action", "Chatbot");
						request.addProperty("question", questionArea.getText());


						Listing listing = currentProgram.getListing();
						FunctionIterator functions = listing.getFunctions(true);
						
						while (functions.hasNext()) {
							Function function = functions.next();

							if (getAllCode || function.getName().equals(functionComboBox.getSelectedItem())) {
								AddressSetView addrSet = function.getBody();
								InstructionIterator codeUnits = listing.getInstructions(addrSet, true);

								JsonArray functionCode = new JsonArray();
								while (codeUnits.hasNext()) {
									CodeUnit codeUnit = codeUnits.next();
									line = new JsonArray();
									line.add(codeUnit.getAddress().toString());
									line.add(codeUnit.toString());
									functionCode.add(line);
								}

								code_asm.add(function.getName(), functionCode);
							}
						}

						request.add("code_asm", code_asm);
						textArea.append(request.toString() + "\n");
						
						// Envoi de la requête POST
						String requestJson = request.toString();
						try {
						    URL url = new URL("http://127.0.0.1:8000/handle_chatbot");
						    HttpURLConnection con = (HttpURLConnection) url.openConnection();
						    con.setRequestMethod("POST");
						    con.setRequestProperty("Content-Type", "application/json; utf-8");
						    con.setRequestProperty("Accept", "application/json");
						    con.setDoOutput(true);

						    try(OutputStream os = con.getOutputStream()) {
						        byte[] input = requestJson.getBytes("utf-8");
						        os.write(input, 0, input.length);           
						    }

						    StringBuilder response = new StringBuilder();
						    try(BufferedReader br = new BufferedReader(
						            new InputStreamReader(con.getInputStream(), "utf-8"))) {
						        String responseLine = null;
						        while ((responseLine = br.readLine()) != null) {
						            response.append(responseLine.trim());
						        }
						    }
						    //
						    // Afficher la réponse pour le débogage
						    textArea.append("Response from API:\n" + response.toString() + "\n");
						}catch (Exception exception) {
					        exception.printStackTrace();
					    }
						/*String query = URLEncoder.encode("Mon message", "UTF-8");

						Msg.info(this, query);

						//URL url = new URL("https://" + query);

						URL url = new URL("https://raversideapi.anthonyvolpelliere.com/");

						BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));

						textArea.append("Request send to : " + "https://raversideapi.anthonyvolpelliere.com/" + "\nResponse : \n");

						String inputLine;
						while ((inputLine = in.readLine()) != null) {
							textArea.append(inputLine + "\n");
						}
						in.close();*/
					
				}
			});

			clear.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					Msg.info(this, "Clear");
					textArea.setText("");
				}


			});
		}

		// TODO: Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);


			actionGetFunctions = new DockingAction("Refresh", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					ProgramManager programManager = tool.getService(ProgramManager.class);
					Program currentProgram = programManager.getCurrentProgram();

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
					functionNames.add(0, "Tout le code");

					SwingUtilities.invokeLater(new Runnable() {
						@Override
						public void run() {
							functionComboBox.setModel(new DefaultComboBoxModel<>(functionNames.toArray(new String[0])));
							functionSubComboBox.setModel(new DefaultComboBoxModel<>(functionNames.toArray(new String[0])));
							functionComboBoxAnalyze.setModel(new DefaultComboBoxModel<>(functionNames.toArray(new String[0])));
						}
					});
				}
			};
			actionGetFunctions.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
			actionGetFunctions.setEnabled(true);
			actionGetFunctions.markHelpUnnecessary();
			dockingTool.addLocalAction(this, actionGetFunctions);

			DockingAction action = new DockingAction("getAsm", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					ProgramManager programManager = tool.getService(ProgramManager.class);
					Program currentProgram = programManager.getCurrentProgram();
					boolean getAllCode = false; // Flag to indicate if we want all code

					// Check if "Tout le code" is selected
					if (functionComboBox.getSelectedItem().equals("Tout le code")) {
						getAllCode = true;
					}

					JsonObject request = new JsonObject();
					JsonObject code_asm = new JsonObject();
					JsonArray line;

					request.addProperty("context", "monContexte");
					request.addProperty("action", "Analyse");
					request.addProperty("type", "vulnérabilité");

					Listing listing = currentProgram.getListing();
					FunctionIterator functions = listing.getFunctions(true);

					while (functions.hasNext()) {
						Function function = functions.next();

						// Check if we want all code or if this is the selected function
						if (getAllCode || function.getName().equals(functionComboBox.getSelectedItem())) {
							AddressSetView addrSet = function.getBody();
							InstructionIterator codeUnits = listing.getInstructions(addrSet, true);

							// Add the function's code to the code_asm JsonObject
							JsonArray functionCode = new JsonArray();
							while (codeUnits.hasNext()) {
								CodeUnit codeUnit = codeUnits.next();
								line = new JsonArray();
								line.add(codeUnit.getAddress().toString());
								line.add(codeUnit.toString());
								functionCode.add(line);
							}

							code_asm.add(function.getName(), functionCode);
						}
					}

					request.add("code_asm", code_asm);
					textArea.append(request.toString() + "\n");
				}
			};

			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);

			action = new DockingAction("getC", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {

					ProgramManager programManager = tool.getService(ProgramManager.class);
					Program currentProgram = programManager.getCurrentProgram();
					DecompInterface decomp = new DecompInterface();
					decomp.openProgram(currentProgram);
					Listing listing = currentProgram.getListing();
					Function selectedFunction = null; // Function variable for the selected function
					boolean getAllCode = false; // Flag to indicate if we want all code

					// Check if "Tout le code" is selected
					if (functionComboBox.getSelectedItem().equals("Tout le code")) {
						getAllCode = true;
					} else {
						// Obtain the selected function
						String selectedFunctionName = (String) functionComboBox.getSelectedItem();
						selectedFunction = getFunctionByName(selectedFunctionName);
					}

					TaskMonitor monitor = tool.getService(ConsoleTaskMonitor.class);

					JsonObject request = new JsonObject();
					JsonObject allFunc = new JsonObject();

					request.addProperty("context", "monContexte");
					request.addProperty("action", "Analyse");
					request.addProperty("type", "vulnérabilité");

					FunctionIterator functions = listing.getFunctions(true);

					while (functions.hasNext()) {
						Function function = functions.next();

						// Check if we want all code or if this is the selected function
						if (getAllCode || function.equals(selectedFunction)) {
							DecompileResults decompRes = decomp.decompileFunction(function, 0, monitor);
							allFunc.addProperty(function.getName(), decompRes.getDecompiledFunction().getC());
						}
					}
					request.add("codeC", allFunc);
					textArea.append(request.toString());

				}
			};

			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);

			functionComboBox.addItemListener(new ItemListener() {
				@Override
				public void itemStateChanged(ItemEvent e) {
					if (e.getStateChange() == ItemEvent.SELECTED) {                        
						String selectedFunctionName = (String) functionComboBox.getSelectedItem();
						Function selectedFunction = getFunctionByName(selectedFunctionName);

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
		
		private void renameSelectedFunctions(List<RenameItem> itemsToRename) {
		    int transactionID = program.startTransaction("Rename Function");
		    try {
		        for (RenameItem item : itemsToRename) {
		            Function function = getFunctionByName(item.getOldName());
		            if (function != null) {
		                function.setName(item.getNewName(), SourceType.USER_DEFINED);
		            }
		        }
		    } catch (Exception e) {
		        // Gérer les exceptions
		    } finally {
		        program.endTransaction(transactionID, true);
		    }
		}
		
		private void renameSelectedVariables(List<RenameItem> itemsToRename) {
		    int transactionID = program.startTransaction("Rename Variables");
		    try {
		        for (RenameItem item : itemsToRename) {
		            Variable variable = getVariableByName(item.getOldName());
		            if (variable != null) {
		                variable.setName(item.getNewName(), SourceType.USER_DEFINED);
		            }
		        }
		    } catch (Exception e) {
		        // Gérer les exceptions
		    } finally {
		        program.endTransaction(transactionID, true);
		    }
		}
		
		private String sendApiRequest(String route, JsonObject request) throws IOException {
		    URL url = new URL("http://127.0.0.1:8000" + route);
		    HttpURLConnection con = (HttpURLConnection) url.openConnection();
		    con.setRequestMethod("POST");
		    con.setRequestProperty("Content-Type", "application/json; utf-8");
		    con.setDoOutput(true);

		    try (OutputStream os = con.getOutputStream()) {
		        byte[] input = request.toString().getBytes("utf-8");
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
		}
		
		private String getAsmCode(Function function) {
		    Listing listing = program.getListing();
		    StringBuilder asmCodeBuilder = new StringBuilder();
		    AddressSetView addrSet = function.getBody();
		    InstructionIterator codeUnits = listing.getInstructions(addrSet, true);

		    while (codeUnits.hasNext()) {
		        CodeUnit codeUnit = codeUnits.next();
		        asmCodeBuilder.append("0x").append(codeUnit.getAddress().toString()).append(" : ").append(codeUnit.toString()).append("\n");
		    }
		    
		    return asmCodeBuilder.toString();
		}

		
		private void setMultilineComment(CodeUnit codeUnit, String comment, int maxLineLength) {
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

	        if (line.length() > 0) {
	            formattedComment.append(line);
	        }

	        codeUnit.setComment(CodeUnit.PLATE_COMMENT, formattedComment.toString());
	    }
		
		

		// Méthode pour récupérer une fonction par son nom
		private Function getFunctionByName(String functionName) {
			ProgramManager programManager = tool.getService(ProgramManager.class);
			Program currentProgram = programManager.getCurrentProgram();
			Listing listing = currentProgram.getListing();
			FunctionIterator functions = listing.getFunctions(true);

			while (functions.hasNext()) {
				Function function = functions.next();
				if (function.getName().equals(functionName)) {
					return function;
				}
			}

			return null; // Retourne null si la fonction n'est pas trouvée
		}

		// Méthode pour récupérer une variable par son nom
		private Variable getVariableByName(String variableName) {
			String selectedFunctionName = (String) functionComboBox.getSelectedItem();
			Function selectedFunction = getFunctionByName(selectedFunctionName);
			if (selectedFunction != null) {
				Variable[] variables = selectedFunction.getAllVariables();
				for (Variable variable : variables) {
					if (variable.getName().equals(variableName)) {
						return variable;
					}
				}
			}
			return null;  // Retourne null si la variable n'est pas trouvée
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
						return false;  // Exclure si la séquence correspond à PUSH/JMP ou ENDBR64/JMP avec seulement deux instructions
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