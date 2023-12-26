package testenvoieassembleur;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class RenameDialog extends JDialog {
	private List<RenameItem> renameItems;
    private List<JCheckBox> checkBoxes;
    private boolean confirmed = false;

    public RenameDialog(Frame owner, List<RenameItem> renameItems) {
        super(owner, "Rename Proposals", true);
        this.renameItems = renameItems;
        this.checkBoxes = new ArrayList<>();
        initUI();
    }


    private List<RenameItem> parseResponse(JsonObject response) {
        List<RenameItem> items = new ArrayList<>();
        JsonArray renames = response.getAsJsonArray("rename");
        if (renames != null) {
            for (int i = 0; i < renames.size(); i++) {
                JsonArray rename = renames.get(i).getAsJsonArray();
                String old_name = rename.get(1).getAsString();
                String new_name = rename.get(2).getAsString();
                items.add(new RenameItem(old_name, new_name));
            }
        }
        return items;
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // Panel for rename items
        JPanel renamePanel = new JPanel();
        renamePanel.setLayout(new BoxLayout(renamePanel, BoxLayout.Y_AXIS));
        JScrollPane scrollPane = new JScrollPane(renamePanel);
        for (RenameItem item : renameItems) {
            JCheckBox checkBox = new JCheckBox(item.getOldName() + " -> " + item.getNewName());
            checkBoxes.add(checkBox);
            renamePanel.add(checkBox);
        }

        // Panel for buttons
        JPanel buttonPanel = new JPanel();
        JButton confirmButton = new JButton("Confirm");
        JButton cancelButton = new JButton("Cancel");

        confirmButton.addActionListener(e -> {
            confirmed = true;
            setVisible(false);
        });

        cancelButton.addActionListener(e -> setVisible(false));

        buttonPanel.add(confirmButton);
        buttonPanel.add(cancelButton);

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setSize(400, 300);
        setLocationRelativeTo(getOwner());
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public List<RenameItem> getSelectedItems() {
        List<RenameItem> selectedItems = new ArrayList<>();
        for (int i = 0; i < checkBoxes.size(); i++) {
            if (checkBoxes.get(i).isSelected()) {
                selectedItems.add(renameItems.get(i));
            }
        }
        return selectedItems;
    }

    public static class RenameItem {
        private String old_name;
        private String new_name;

        public RenameItem(String old_name, String new_name) {
            this.old_name = old_name;
            this.new_name = new_name;
        }

        public String getOldName() {
            return old_name;
        }

        public String getNewName() {
            return new_name;
        }
    }
}

