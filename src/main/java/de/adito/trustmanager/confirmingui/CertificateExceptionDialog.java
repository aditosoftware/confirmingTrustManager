package de.adito.trustmanager.confirmingui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.Locale;
import java.util.ResourceBundle;

class CertificateExceptionDialog extends JDialog {

    private JPanel mainPanel;
    private JPanel extButtonPanel;
    private JScrollPane extScrollPane;

    private ResourceBundle bundle;
    private boolean isExtended;
    private int buttonChoice;
    private String detailMsg;

    CertificateExceptionDialog(String pDetailMessage){
        super((Frame)null, true);
        this.buttonChoice = -1;
        this.isExtended = false;
        this.detailMsg = pDetailMessage;
        bundle = ResourceBundle.getBundle("de.adito.trustmanager.detailMessage", Locale.getDefault());

        _createFirstDialog();
    }

    private void _createFirstDialog() {

        setTitle(bundle.getString("frameTitle"));
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        mainPanel = new JPanel(new GridBagLayout());

        JTextArea dialog = new JTextArea(bundle.getString("unextedText"));
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

        JButton extendDialog = new JButton(bundle.getString("extDialog"));
        JButton cancel = new JButton(bundle.getString("cancel"));
        cancel.addActionListener(pEvent -> {
            buttonChoice = 2;
            dispose();
        });
        extendDialog.addActionListener(pEvent -> {
            if (!isExtended) {
                isExtended = true;
                _createExtendedDialog();
            } else {
                isExtended = false;
                _hideExtendedDialog();
            }
        });

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(extendDialog);
        buttonPanel.add(cancel);

        GridBagConstraints constraintsButton = new GridBagConstraints();
        constraintsButton.gridx = 1;
        constraintsButton.gridy = 1;
        constraintsButton.insets = new Insets(0, 0, 0, 2);
        constraintsButton.anchor = GridBagConstraints.LAST_LINE_END;

        ActionListener keyAction = pressedKey -> dispose();
        getRootPane().registerKeyboardAction(keyAction, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

        mainPanel.add(scrollPane, constraintText);
        mainPanel.add(buttonPanel, constraintsButton);
        add(mainPanel);

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

        extScrollPane = new JScrollPane(extendedDialog);
        GridBagConstraints textConstraints = new GridBagConstraints();
        textConstraints.gridx = 0;
        textConstraints.gridy = 2;
        textConstraints.gridwidth = 2;
        textConstraints.gridheight = 1;
        textConstraints.anchor = GridBagConstraints.CENTER;

        //Button Handling
        JButton trust = new JButton(bundle.getString("trust"));
        JButton trustOnce = new JButton(bundle.getString("trustOnce"));
        trust.addActionListener(pEvent -> {
            buttonChoice = 1;
            dispose();
        });
        trustOnce.addActionListener(pEvent ->{
            buttonChoice = 0;
            dispose();
        });

        extButtonPanel = new JPanel();
        extButtonPanel.add(trust);
        extButtonPanel.add(trustOnce);

        GridBagConstraints button2 = new GridBagConstraints();
        button2.gridx = 1;
        button2.gridy = 3;
        button2.insets = new Insets(0,0,0,2);
        button2.anchor = GridBagConstraints.LAST_LINE_END;

        mainPanel.add(extScrollPane, textConstraints);
        mainPanel.add(extButtonPanel, button2);

        pack();
        validate();
        repaint();

    }

    private void _hideExtendedDialog() {
        mainPanel.remove(extScrollPane);
        mainPanel.remove(extButtonPanel);
        pack();
        validate();
        repaint();

    }

    int getButtonChoice() {
        return buttonChoice;
    }
}
