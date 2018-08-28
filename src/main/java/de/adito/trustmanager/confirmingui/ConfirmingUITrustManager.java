package de.adito.trustmanager.confirmingui;

import de.adito.trustmanager.CustomTrustManagerHandler;
import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

/**
 * This class calls CustomTrustManagerHandler, which will handle the certificateException, creates a SSLContext and also prompts
 * the JDialog to be shown
 */

public class ConfirmingUITrustManager extends CustomTrustManagerHandler {

  private ConfirmingUITrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException,
      IOException, CertificateException, InvalidAlgorithmParameterException
  {
    super(pTrustStore);
  }

  public static SSLContext createSslContext(ICustomTrustStore pTrustStore) throws CertificateException, InvalidAlgorithmParameterException,
      NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException
  {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    CustomTrustManagerHandler trustManager = new ConfirmingUITrustManager(pTrustStore);
    sslContext.init(null, new CustomTrustManagerHandler[]{trustManager}, new SecureRandom());
    return sslContext;
  }

  protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pCertExc, String pSimpleInfo)
          throws CertificateException {

    CertificateExceptionDetail certExcDetail = CertificateExceptionDetail.createExceptionDetail(pChain, pCertExc, pSimpleInfo);
    String detailMessage = certExcDetail.makeExceptionMessage(pSimpleInfo);

    CertificateExceptionDialog certExceptionDialog = new CertificateExceptionDialog(detailMessage);
    certExceptionDialog.setVisible(true);

    int r = certExceptionDialog.getButtonChoice();  //returns selected button as int
    switch (r){    // Will decide to trust or not trust the certificate
      case 0:       //trust once
        return false;
      case 1:       //add certificate permanently
        return true;
      default:
        throw pCertExc;  //cancel
    }
  }
}
