package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public abstract class CustomTrustManager extends X509ExtendedTrustManager
{
  private final List<X509ExtendedTrustManager> defaultTrustManagers;
  private ICustomTrustStore trustStore;

  public CustomTrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException, IOException,
          CertificateException, InvalidAlgorithmParameterException {
    defaultTrustManagers = new ArrayList<>();
    trustStore = pTrustStore;

    // initialize certification path checking for the offered certificates and revocation checks against CLRs
    CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
    PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
    revocationChecker.setOptions(EnumSet.of(
            PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
            PKIXRevocationChecker.Option.ONLY_END_ENTITY,
            PKIXRevocationChecker.Option.SOFT_FAIL, // handshake should not fail when CRL is not available
            PKIXRevocationChecker.Option.NO_FALLBACK)); // don't fall back to OCSP checking

    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

    KeyManagerFactory winKeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    KeyStore winKeyStore = KeyStore.getInstance("Windows-ROOT");
    winKeyStore.load(null, null);
    try {
      winKeyManagerFactory.init(winKeyStore, null);
    } catch (UnrecoverableKeyException e) {
      e.printStackTrace();
    }

    PKIXBuilderParameters winPkixParams = new PKIXBuilderParameters(winKeyStore, new X509CertSelector());
    winPkixParams.addCertPathChecker(revocationChecker);
    trustManagerFactory.init(new CertPathTrustManagerParameters(winPkixParams));
    javax.net.ssl.TrustManager[] winTM = trustManagerFactory.getTrustManagers();

    //initialize second truststore

    String javaKeyStorePath = System.getProperty("javax.net.ssl.keyStore");
    if (javaKeyStorePath == null) {
      String securityPath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator;
      if (Files.isRegularFile(Paths.get(securityPath + "jssecacerts")))
        javaKeyStorePath = securityPath + "jssecacerts";
      else if (Files.isRegularFile(Paths.get(securityPath + "cacerts")))
        javaKeyStorePath = securityPath + "cacerts";
    }
    String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword", "changeit");
    KeyStore JKSKeyStore = KeyStore.getInstance("JKS");
    TrustManagerUtil.loadKeyStore(JKSKeyStore, keyStorePassword, javaKeyStorePath == null ? null : Paths.get(javaKeyStorePath));

    PKIXBuilderParameters javaPkixParams = new PKIXBuilderParameters(JKSKeyStore, new X509CertSelector());
    javaPkixParams.addCertPathChecker(revocationChecker);
    trustManagerFactory.init(new CertPathTrustManagerParameters(javaPkixParams));
    javax.net.ssl.TrustManager[] javaTM= trustManagerFactory.getTrustManagers();

    if (javaTM.length == 0 || winTM.length == 0)
      throw new IllegalStateException("No trust managers found");

    defaultTrustManagers.add((X509ExtendedTrustManager) javaTM[0]);
    defaultTrustManagers.add((X509ExtendedTrustManager) winTM[0]);
  }

  public X509Certificate[] getAcceptedIssuers() {
    List<X509Certificate> certificates = new LinkedList<>();
    for (X509ExtendedTrustManager trustManager : defaultTrustManagers) {
      certificates.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
    }
    return certificates.toArray(new X509Certificate[certificates.size()]);
  }

  public void checkClientTrusted(X509Certificate[] chain, String authType)
  {
    throw new UnsupportedOperationException("checkClientTrusted");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket pSocket)
  {
    throw new UnsupportedOperationException("checkClientTrusted");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine pSSLEngine)
  {
    throw new UnsupportedOperationException("checkClientTrusted");
  }

  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
  {
    for(X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers) {
      try {
        defaultTrustManager.checkServerTrusted(chain, authType);

      } catch (CertificateException e) {
        _handleCertificateException(chain, e, null);
      }
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket pSocket) throws CertificateException
  {
    for(X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers) {
      try {
        defaultTrustManager.checkServerTrusted(chain, authType, pSocket);

      } catch (CertificateException e) {
        _handleCertificateException(chain, e, pSocket.getInetAddress().getHostName());
      }
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine pSSLEngine) throws CertificateException
  {
    for(X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers) {
      try {
        defaultTrustManager.checkServerTrusted(chain, authType, pSSLEngine);

      } catch (CertificateException e) {
        _handleCertificateException(chain, e, pSSLEngine.getPeerHost());
      }
    }
  }

  private void _handleCertificateException(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) throws CertificateException
  {
    if (pChain == null || pChain.length == 0)
      throw pE;
    Throwable cause = pE.getCause();
    if (cause instanceof CertPathValidatorException) {
      Throwable rootCause = cause.getCause();
      if (rootCause instanceof CertificateRevokedException)
        throw pE;
    }

    tryCustomTrustManager(pChain, pE, pSimpleInfo);

  }

  private void tryCustomTrustManager(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
      throws CertificateException
  {
    {
      X509Certificate certificate = pChain[pChain.length - 1];
      String alias = TrustManagerUtil.hashSHA1(certificate);
      if (trustStore.get(alias) != null)
        return;
      boolean persist = checkCertificateAndShouldPersist(pChain, pE, pSimpleInfo);
      trustStore.add(alias, certificate, persist);
    }
  }

  protected abstract boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
      throws CertificateException;
}