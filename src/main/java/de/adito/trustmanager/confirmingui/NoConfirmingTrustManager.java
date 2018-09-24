package de.adito.trustmanager.confirmingui;

import de.adito.trustmanager.CustomTrustManager;
import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.*;

/**
 * @author j.boesl, 21.09.18
 */
public class NoConfirmingTrustManager extends CustomTrustManager
{
  public NoConfirmingTrustManager(ICustomTrustStore pTrustStore, Iterable<X509ExtendedTrustManager> pTrustManagers)
  {
    super(pTrustStore, pTrustManagers);
  }

  @Override
  protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) throws CertificateException
  {
    throw pE;
  }
}
