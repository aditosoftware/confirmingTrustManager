package de.adito.trustmanager.confirmingui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class CertificateExceptionDialog extends JDialog {

    private JPanel mainPanel;
    private JButton extendDialog;
    private JButton trust;
    private JButton trustOnce;
    private JPanel buttonPanel2;
    private JScrollPane scrollPane;

    private boolean isExtended;
    private int buttonChoice;
    private String detailMsg;

    public CertificateExceptionDialog(String pDetailMessage){
        super((Frame)null, true);
        this.buttonChoice = -1;
        this.isExtended = false;
        this.detailMsg = pDetailMessage;
        _createFirstDialog();
    }

    private void _createFirstDialog() {
        String msg = "Es liegt ein Problem mit dem Sicherheitszertifikat der Verbindung vor.\n\n" +
                "Das Zertifikat konnte nicht verifiziert werden.\n\n" +
                "Sie können den Vorgang abbrechen, oder in den erweiterten Einstellungen bearbeiten.";

        setTitle("Zertifikat Management");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        mainPanel = new JPanel(new GridBagLayout());

        JTextArea dialog = new JTextArea(msg);
        dialog.setEditable(false);
        dialog.setOpaque(false);

        JScrollPane scrollPane = new JScrollPane(dialog);
        scrollPane.setBorder(null);

        GridBagConstraints constraintText = new GridBagConstraints();
        constraintText.weightx = 1.0;
        constraintText.gridx = 0;
        constraintText.gridy = 0;
        constraintText.gridwidth = 2;
        constraintText.gridheight = 1;
        constraintText.anchor = GridBagConstraints.CENTER;

        extendDialog = new JButton("Erweitern");
        JButton cancel = new JButton("Abbrechen");
        extendDialog.addActionListener(pEvent -> _interpretClickedButton(pEvent));
        cancel.addActionListener(pEvent -> _interpretClickedButton(pEvent));

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(extendDialog);
        buttonPanel.add(cancel);
        GridBagConstraints constraintsButton = new GridBagConstraints();
        constraintsButton.gridx = 1;
        constraintsButton.gridy = 1;
        constraintsButton.insets = new Insets(0, 0, 0, 2);
        constraintsButton.anchor = GridBagConstraints.LAST_LINE_END;

        mainPanel.add(scrollPane, constraintText);
        mainPanel.add(buttonPanel, constraintsButton);
        add(mainPanel);

        //uncomment after finishing debugging
        setAlwaysOnTop(true);
        setResizable(false);
        setMinimumSize(new Dimension(500, 140));
        pack();
        setLocationRelativeTo(null);
    }

    private void _createExtendedDialog() {
        //Text Handling
        JTextArea extendedDialog = new JTextArea(detailMsg);
        extendedDialog.setEditable(false);
        extendedDialog.setOpaque(false);

        scrollPane = new JScrollPane(extendedDialog);
        GridBagConstraints textConstraints = new GridBagConstraints();
        textConstraints.gridx = 0;
        textConstraints.gridy = 2;
        textConstraints.gridwidth = 2;
        textConstraints.gridheight = 1;
        textConstraints.anchor = GridBagConstraints.CENTER;

        //Button Handling
        trust = new JButton("Ausnahme hinzufügen");
        trustOnce = new JButton("Einmalig vertrauen");
        trust.addActionListener(pEvent -> _interpretClickedButton(pEvent));
        trustOnce.addActionListener(pEvent -> _interpretClickedButton(pEvent));

        buttonPanel2 = new JPanel();
        buttonPanel2.add(trust);
        buttonPanel2.add(trustOnce);
        GridBagConstraints button2 = new GridBagConstraints();
        button2.gridx = 1;
        button2.gridy = 3;
        button2.insets = new Insets(0,0,0,2);
        button2.anchor = GridBagConstraints.LAST_LINE_END;

        mainPanel.add(scrollPane, textConstraints);
        mainPanel.add(buttonPanel2, button2);

        pack();
        validate();
        repaint();

    }

    private void _hideExtendedDialog() {
        mainPanel.remove(scrollPane);
        mainPanel.remove(buttonPanel2);
        pack();
        validate();
        repaint();

    }

    private void _interpretClickedButton(ActionEvent pEvent) {

        if (pEvent.getSource() == extendDialog) {
            if (!isExtended) {
                isExtended = true;
                _createExtendedDialog();
            } else {
                isExtended = false;
                _hideExtendedDialog();
            }

        } else if (pEvent.getSource() == trustOnce) {
            buttonChoice = 0;
            this.dispose();

        } else if (pEvent.getSource() == trust) {
            buttonChoice = 1;
            this.dispose();

        } else { //cancel
            buttonChoice = 2;
            this.dispose();

        }
    }

    public int getButtonChoice() {
        return buttonChoice;
    }
}
