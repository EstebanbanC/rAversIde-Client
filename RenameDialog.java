package raverside;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;


import ghidra.program.model.listing.Function;

public class RenameDialog extends JDialog {
	private List<RenameItem> renameItems;
    protected List<JCheckBox> checkBoxes;
    private boolean confirmed = false;

    public RenameDialog(Frame owner, List<RenameItem> renameItems) {
        super(owner, "Rename Proposals", true);
        this.renameItems = renameItems;
        this.checkBoxes = new ArrayList<>();
        initUI();
    }


    protected void initUI() {
        setLayout(new BorderLayout());

        JPanel renamePanel = createRenamePanel();
        JScrollPane scrollPane = new JScrollPane(renamePanel);
        JPanel buttonPanel = createButtonPanel();

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        setSize(400, 300);
        setLocationRelativeTo(getOwner());
    }

    protected JPanel createRenamePanel() {
        JPanel renamePanel = new JPanel();
        renamePanel.setLayout(new BoxLayout(renamePanel, BoxLayout.Y_AXIS));

        for (RenameItem item : renameItems) {
            JCheckBox checkBox = new JCheckBox(formatRenameText(item));
            checkBoxes.add(checkBox);
            renamePanel.add(checkBox);
        }

        return renamePanel;
    }

    private String formatRenameText(RenameItem item) {
        return item.getOldName() + " -> " + item.getNewName();
    }

    protected JPanel createButtonPanel() {
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

        return buttonPanel;
    }

    protected boolean isConfirmed() {
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
        private String item_type;
        private Function function;

        public RenameItem(String old_name, String new_name, String item_type, Function function) {
            this.old_name = old_name;
            this.new_name = new_name;
            this.item_type = item_type;
            this.function = function;
        }

        public String getOldName() {
            return old_name;
        }

        public String getNewName() {
            return new_name;
        }
        
        public String getItemType() {
        	return item_type;
        }
        
        public Function getFunction() {
            return function;
        }
        
        @Override
        public String toString() {
            return "RenameItem{" +
                    "oldName='" + old_name + '\'' +
                    ", newName='" + new_name + '\'' +
                    ", itemType='" + item_type + '\'' +
                    ", function=" + (function != null ? function.getName() : "null") +
                    '}';
        }
    }
}
