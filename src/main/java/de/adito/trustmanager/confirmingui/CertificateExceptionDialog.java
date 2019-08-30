package de.adito.trustmanager.confirmingui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.Locale;
import java.util.ResourceBundle;

/**
 * This class builds a JDialog with the before determined exceptionDetail from {@link CertificateExceptionDetail}.
 * 'buttonChoice' will be used to decide what to do with the exception in {@link ConfirmingUITrustManager}.
 * -1: Dialog was closed or Esc was pressed, 0: trust once, 1: trust permanently, 2: cancel
 * -1 and 2 will end in a certificateException.
 */

class CertificateExceptionDialog extends JDialog
{
    
    private JPanel extButtonPanel;
    private JComponent extendedDialog;
    
    private ResourceBundle bundle;
    private boolean isExtended;
    private int buttonChoice;
    private String detailMsg;
    
    CertificateExceptionDialog(String pDetailMessage)
    {
        super((Frame) null, true);
        this.buttonChoice = -1;
        this.isExtended = false;
        this.detailMsg = pDetailMessage;
        bundle = ResourceBundle.getBundle("de.adito.trustmanager.dialogMessage", Locale.getDefault());

        _createFirstDialog();
    }
    
    private void _createFirstDialog()
    {
        setTitle(bundle.getString("frameTitle"));
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new GridBagLayout());
        
        JTextArea dialog = new JTextArea(bundle.getString("unextedText"));
        dialog.setEditable(false);
        dialog.setOpaque(false);

        GridBagConstraints constraintText = new GridBagConstraints();
        constraintText.weightx = 1.0;
        constraintText.gridx = 0;
        constraintText.gridy = 0;
        constraintText.gridwidth = 2;
        constraintText.gridheight = 1;
        constraintText.insets = new Insets(5, 30, 5, 30);
        constraintText.anchor = GridBagConstraints.CENTER;
        
        JButton extendDialog = new JButton(bundle.getString("extDialog"));
        JButton cancel = new JButton(bundle.getString("cancel"));
        cancel.addActionListener(pEvent ->
        {
            buttonChoice = 2;
            dispose();
        });
        extendDialog.addActionListener(pEvent ->
        {
            if (!isExtended)
            {
                isExtended = true;
                _createExtendedDialog();
            } else
            {
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
        constraintsButton.insets = new Insets(0, 5, 5, 5);
        constraintsButton.anchor = GridBagConstraints.LAST_LINE_END;
        
        ActionListener keyAction = pressedKey -> dispose();
        getRootPane().registerKeyboardAction(keyAction, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

        add(dialog, constraintText);
        add(buttonPanel, constraintsButton);
        
        setAlwaysOnTop(true);
        setResizable(false);
        pack();
        setLocationRelativeTo(null);
    }
    
    private void _createExtendedDialog()
    {
        //Text Handling
        JTextArea extendedDialogArea = new JTextArea(detailMsg);
        extendedDialogArea.setEditable(false);
        extendedDialogArea.setOpaque(false);
        JScrollPane scrollPane = new JScrollPane(extendedDialogArea);
        scrollPane.setBorder(null);
        extendedDialog = new JPanel(new BorderLayout());
        extendedDialog.setPreferredSize(new Dimension(getPreferredSize().width - 20, 200));
        extendedDialog.add(scrollPane, BorderLayout.CENTER);
        extendedDialog.setBorder(BorderFactory.createEtchedBorder());

        GridBagConstraints textConstraints = new GridBagConstraints();
        textConstraints.gridx = 0;
        textConstraints.gridy = 2;
        textConstraints.gridwidth = 2;
        textConstraints.gridheight = 1;
        textConstraints.insets = new Insets(5, 0, 5, 0);
        textConstraints.anchor = GridBagConstraints.CENTER;
        
        //Button Handling
        JButton trust = new JButton(bundle.getString("trust"));
        JButton trustOnce = new JButton(bundle.getString("trustOnce"));
        trust.addActionListener(pEvent ->
        {
            buttonChoice = 1;
            dispose();
        });
        trustOnce.addActionListener(pEvent ->
        {
            buttonChoice = 0;
            dispose();
        });
        
        extButtonPanel = new JPanel();
        extButtonPanel.add(trust);
        extButtonPanel.add(trustOnce);
        
        GridBagConstraints button2 = new GridBagConstraints();
        button2.gridx = 1;
        button2.gridy = 3;
        button2.insets = new Insets(0, 5, 5, 5);
        button2.anchor = GridBagConstraints.LAST_LINE_END;

        add(extendedDialog, textConstraints);
        add(extButtonPanel, button2);

        pack();
        validate();
        repaint();
    }
    
    private void _hideExtendedDialog()
    {
        remove(extendedDialog);
        remove(extButtonPanel);
        pack();
        validate();
        repaint();
    }
    
    int getButtonChoice()
    {
        return buttonChoice;
    }
}
