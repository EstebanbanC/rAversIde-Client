package raverside;

import org.junit.Before;
import org.junit.Test;

import raverside.RenameDialog;
import raverside.RenameDialog.RenameItem;

import static org.junit.Assert.*;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;

public class RenameDialogTest {
    private RenameDialog renameDialog;
    private List<RenameItem> renameItems;

    @Before
    public void setUp() {
        // Créer une liste de RenameItems pour le test
        renameItems = new ArrayList<>();
        renameItems.add(new RenameItem("oldName1", "newName1", "type1", null));
        renameItems.add(new RenameItem("oldName2", "newName2", "type2", null));
        
        // Initialiser RenameDialog (peut nécessiter des ajustements selon l'environnement de test)
        renameDialog = new RenameDialog(null, renameItems);
    }

    @Test
    public void testInitUI() {
        renameDialog.initUI();

        // Vérifiez que le layout principal est BorderLayout
        assertTrue(renameDialog.getLayout() instanceof BorderLayout);

        // Vérifiez la présence du JScrollPane et du JPanel pour les boutons
        Component[] components = renameDialog.getContentPane().getComponents();
        assertTrue(components[0] instanceof JScrollPane);
        assertTrue(components[1] instanceof JPanel);

        // Vérifiez la taille et la position du dialog
        assertEquals(400, renameDialog.getSize().width);
        assertEquals(300, renameDialog.getSize().height);
    }

    @Test
    public void testCreateRenamePanel() {
        JPanel renamePanel = renameDialog.createRenamePanel();

        // Vérifiez que le layout du panel est BoxLayout
        assertTrue(renamePanel.getLayout() instanceof BoxLayout);

        // Vérifiez que chaque RenameItem correspond à un JCheckBox dans le panel
        Component[] components = renamePanel.getComponents();
        assertEquals(renameItems.size(), components.length);

        for (int i = 0; i < components.length; i++) {
            assertTrue(components[i] instanceof JCheckBox);
            JCheckBox checkBox = (JCheckBox) components[i];
            assertEquals(renameItems.get(i).getOldName() + " -> " + renameItems.get(i).getNewName(), checkBox.getText());
        }
    }

    @Test
    public void testCreateButtonPanel() {
        JPanel buttonPanel = renameDialog.createButtonPanel();

        // Vérifiez la présence des boutons
        assertEquals(2, buttonPanel.getComponentCount());

        Component comp1 = buttonPanel.getComponent(0);
        Component comp2 = buttonPanel.getComponent(1);

        assertTrue(comp1 instanceof JButton);
        assertTrue(comp2 instanceof JButton);

        JButton confirmButton = (JButton) comp1;
        JButton cancelButton = (JButton) comp2;

        assertEquals("Confirm", confirmButton.getText());
        assertEquals("Cancel", cancelButton.getText());

        // Vérifiez que les ActionListeners sont attachés
        assertTrue(confirmButton.getActionListeners().length > 0);
        assertTrue(cancelButton.getActionListeners().length > 0);
    }

    @Test
    public void testGetSelectedItems() {
        // Simuler la sélection de quelques cases à cocher
        for (int i = 0; i < renameDialog.checkBoxes.size(); i++) {
            JCheckBox checkBox = renameDialog.checkBoxes.get(i);
            checkBox.setSelected(i % 2 == 0);  // Sélectionner chaque deuxième élément
        }

        List<RenameDialog.RenameItem> selectedItems = renameDialog.getSelectedItems();

        // Vérifier que la liste retournée contient les bons éléments
        assertNotNull(selectedItems);
        assertEquals(renameDialog.checkBoxes.size() / 2, selectedItems.size());
        for (int i = 0; i < selectedItems.size(); i++) {
            assertEquals(renameItems.get(i * 2), selectedItems.get(i));
        }
    }
}
