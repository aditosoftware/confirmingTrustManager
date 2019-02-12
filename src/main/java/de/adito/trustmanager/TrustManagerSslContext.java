package de.adito.trustmanager;

import de.adito.trustmanager.store.*;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * @author j.boesl, 20.09.18
 */
public class TrustManagerSslContext
{
  private TrustManagerSslContext()
  {
  }

  public static void initSslContext() throws CertificateException, InvalidAlgorithmParameterException,
      NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException
  {
    initSslContext(new JKSCustomTrustStore());
  }

  public static void initSslContext(ICustomTrustStore pTrustStore) throws CertificateException, InvalidAlgorithmParameterException,
      NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException
  {
    initSslContext(TrustManagerBuilder.buildConfirmingTrustManager(pTrustStore, true));
  }

  public static void initSslContext(TrustManager pTrustManager) throws NoSuchAlgorithmException, KeyManagementException
  {
    KeyManagerFactory instance = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(instance.getKeyManagers(), new TrustManager[]{pTrustManager}, new SecureRandom());
    SSLContext.setDefault(sslContext);
  }
}
