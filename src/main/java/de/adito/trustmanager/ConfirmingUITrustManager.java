package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static java.lang.String.format;

public class ConfirmingUITrustManager extends CustomTrustManager {

    public ConfirmingUITrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, InvalidAlgorithmParameterException {
        super(pTrustStore);
    }

    protected boolean checkCertificateAndShouldPersist(
            X509Certificate[] chain, CertificateException e)
            throws CertificateException {

        String[] options;
        options = new String[]{
                "yes once",
                "yes always",
                "no"
        };
        String dn = chain[0].getSubjectDN().getName();
        String caDN = chain[0].getIssuerX500Principal().getName();
        String msg = format(e.getLocalizedMessage() + "\n" +
                        "\n" +
                        "subject common name: %1$s\n" +
                        "subject organization name: %2$s\n" +
                        "principal common name: %3$s\n" +
                        "principal organziation name: %4$s\n" +
                        "valid since: %5$s\n" +
                        "valid till: %6$s\n" +
                        "sha1 hash: %7$s\n" +
                        "md5 hash: %8$s\n" +
                        "\n" +
                        "%9$s",
                TrustManagerUtil.parseDN(dn, "cn"),
                TrustManagerUtil.parseDN(dn, "o"),
                TrustManagerUtil.parseDN(caDN, "cn"),
                TrustManagerUtil.parseDN(caDN, "o"),
                chain[0].getNotBefore(),
                chain[0].getNotAfter(),
                TrustManagerUtil.hashSHA1(chain[0]),
                TrustManagerUtil.hashMD5(chain[0]),
                chain[0].toString());

        JTextArea textArea = new JTextArea(msg);
        JScrollPane scrollPane = new JScrollPane(textArea);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        scrollPane.setPreferredSize(new Dimension(640, 400));

        int r = JOptionPane.showOptionDialog(null, scrollPane,
                "certificate is not trusted",
                JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
                null, options, options[1]);
        switch (r) {
            case 0:
                return false;
            case 1:
                return true;
            default:
                throw e;
        }
    }
}
