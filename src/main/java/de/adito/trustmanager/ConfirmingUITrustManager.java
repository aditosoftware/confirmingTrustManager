package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.SSLContext;
import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

public class ConfirmingUITrustManager extends CustomTrustManager
{

  public ConfirmingUITrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException,
      IOException, CertificateException, InvalidAlgorithmParameterException
  {
    super(pTrustStore);
  }

  public static SSLContext createSslContext(ICustomTrustStore pTrustStore) throws CertificateException, InvalidAlgorithmParameterException,
      NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException
  {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    CustomTrustManager trustManager = new ConfirmingUITrustManager(pTrustStore);
    sslContext.init(null, new CustomTrustManager[]{trustManager}, new SecureRandom());
    return sslContext;
  }

  protected boolean checkCertificateAndShouldPersist(X509Certificate[] chain, CertificateException e, String pSimpleInfo)
      throws CertificateException
  {
    JTextArea textArea = new JTextArea(
        "The owner of '" + pSimpleInfo + "' has configured their website improperly. " +
            "To protect your information from being stolen the connection to the target is interrupted.");
    textArea.setEditable(false);
    textArea.setOpaque(false);
    textArea.setLineWrap(true);
    textArea.setWrapStyleWord(true);
    JScrollPane scrollPane = new JScrollPane(textArea);
    scrollPane.setBorder(null);
    scrollPane.setPreferredSize(new Dimension(640, 400));


    String[] options = new String[]{
        "Cancel",
        "Advanced"
    };
    int r = JOptionPane.showOptionDialog(
        null, scrollPane,
        "Your connection is not secure",
        JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
        null, options, options[0]);

    switch (r) {
      case 1:
        return _extendedDialog(chain, e, pSimpleInfo);
      case 0:
      default:
        throw e;
    }
  }

  protected boolean _extendedDialog(X509Certificate[] chain, CertificateException e, String pSimpleInfo) throws CertificateException
  {
    String[] options = new String[]{
        "ignore",
        "import",
        "deny"
    };
    String dn = chain[0].getSubjectDN().getName();
    String caDN = chain[0].getIssuerX500Principal().getName();
    String msg = String.format(
        e.getLocalizedMessage() + "\n" +
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
    textArea.setEditable(false);
    textArea.setOpaque(false);
    textArea.setLineWrap(true);
    textArea.setWrapStyleWord(true);
    JScrollPane scrollPane = new JScrollPane(textArea);
    scrollPane.setBorder(null);
    scrollPane.setPreferredSize(new Dimension(640, 400));

    int r = JOptionPane.showOptionDialog(
        null, scrollPane,
        "certificate of '" + pSimpleInfo + "' is not trusted",
        JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
        null, options, options[2]);

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
