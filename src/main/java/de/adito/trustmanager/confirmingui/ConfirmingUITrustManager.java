package de.adito.trustmanager.confirmingui;


import de.adito.trustmanager.CustomTrustManager;
import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;


public class ConfirmingUITrustManager extends CustomTrustManager {

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

  protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pCertExc, String pSimpleInfo)
          throws CertificateException {

    String detailMessage = CertificateExceptionDetail.createExceptionDetail(pChain, pCertExc, pSimpleInfo);
    CertificateExceptionDialog certExceptionDialog = new CertificateExceptionDialog(detailMessage);
    certExceptionDialog.setVisible(true);

    int r = certExceptionDialog.getChoice();  //returns selected button as int
    switch (r){    // Will decide to trust or not trust the certificate
      case 0:       //trust once
        return false;
      case 1:       //add exception
        return true;
      default:
        throw pCertExc;  //cancel
    }
  }
}
