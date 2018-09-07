package de.adito.trustmanager.confirmingui;

import de.adito.trustmanager.CustomTrustManager;
import de.adito.trustmanager.store.ICustomTrustStore;
import de.adito.trustmanager.store.JKSCustomTrustStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

/**
 * This class creates a SSLContext and implements checkCertificateAndShouldPersist used in {@link CustomTrustManager}
 */
public class ConfirmingUITrustManager extends CustomTrustManager
{

  public ConfirmingUITrustManager(ICustomTrustStore pTrustStore, Iterable<X509ExtendedTrustManager> pTrustManagers)
  {
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
    CustomTrustManager trustManager = new ConfirmingUITrustManager(pTrustStore, createStandardTrustManagers());
    sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
    return sslContext;
  }

  /**
   * This method handles the JDialog and its return value
   */
  protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pCertExc, String pSimpleInfo)
          throws CertificateException
  {
    CertificateExceptionDetail certExcDetail = CertificateExceptionDetail.createExceptionDetail(pChain, pCertExc, pSimpleInfo);
    String detailMessage = certExcDetail.makeExceptionMessage(pSimpleInfo);
    
    int r = _createDialog(detailMessage);  //returns selected button as int
    switch (r){    // Will decide to trust or not trust the certificate
      case 0:       //trust once
        return false;
      case 1:       //add certificate permanently
        return true;
      default:
        throw pCertExc;  //cancel
    }
  }
  private int _createDialog(String pDetailMessage)
  {
      CertificateExceptionDialog certExceptionDialog = new CertificateExceptionDialog(pDetailMessage);
      certExceptionDialog.setVisible(true);
    
      return certExceptionDialog.getButtonChoice();
  }
}
