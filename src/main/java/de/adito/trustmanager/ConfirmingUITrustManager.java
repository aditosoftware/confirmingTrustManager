package de.adito.trustmanager;


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

  protected boolean checkCertificateAndShouldPersist(X509Certificate[] chain, CertificateException e, String pSimpleInfo)
          throws CertificateException {

    DetailMessageFrame detailMessageFrame = new DetailMessageFrame(pSimpleInfo, e, chain);
    detailMessageFrame.setVisible(true);
    int r = detailMessageFrame.getChoice();

    switch (r){    // Will decide to trust or not trust the certificate
      case 0:       //trust once
        return false;
      case 1:       //add exception
        return true;
      default:
        throw e;  //cancel
    }
  }
}
