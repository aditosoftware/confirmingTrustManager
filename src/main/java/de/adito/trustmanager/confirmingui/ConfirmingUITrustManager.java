package de.adito.trustmanager.confirmingui;

import de.adito.trustmanager.manager.CustomTrustManagerHandler;
import de.adito.trustmanager.store.ICustomTrustStore;
import de.adito.trustmanager.store.JKSCustomTrustStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

/**
 * This class creates a SSLContext, calls CustomTrustManagerHandler, which will handle the certificateException and also prompts
 * the JDialog to be shown & interprets buttonChoice
 */

public class ConfirmingUITrustManager extends CustomTrustManagerHandler {

  public ConfirmingUITrustManager(ICustomTrustStore pTrustStore, Iterable<X509ExtendedTrustManager> pTrustManagers) {
    super(pTrustStore, pTrustManagers);
  }


  public static SSLContext createSslContext() throws CertificateException, InvalidAlgorithmParameterException,
          NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException
  {
    return createSslContext(new JKSCustomTrustStore());
  }

  public static SSLContext createSslContext(ICustomTrustStore pTrustStore) throws CertificateException, InvalidAlgorithmParameterException,
      NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException
  {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    CustomTrustManagerHandler trustManager = new ConfirmingUITrustManager(pTrustStore, createStandardTrustManagers());
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
