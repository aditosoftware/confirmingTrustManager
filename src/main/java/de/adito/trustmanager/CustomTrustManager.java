package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public abstract class CustomTrustManager extends X509ExtendedTrustManager
{
  private final List<X509ExtendedTrustManager> defaultTrustManagers;
  private ICustomTrustStore trustStore;
  private boolean certAccepted;

  public CustomTrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException, IOException,
          CertificateException, InvalidAlgorithmParameterException {
    certAccepted = false;
    defaultTrustManagers = new ArrayList<>();
    trustStore = pTrustStore;

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
    keyStore.load(null, null);
    try {
      keyManagerFactory.init(keyStore, null);
    } catch (UnrecoverableKeyException e) {
      e.printStackTrace();
    }

    tmf.init(keyStore);

    javax.net.ssl.TrustManager[] tm = tmf.getTrustManagers();
    if (tm.length == 0)
      throw new IllegalStateException("No trust managers found");
    defaultTrustManagers.add((X509ExtendedTrustManager) tm[0]);

    //initialize second truststore

    TrustManagerFactory tmf1 = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

    // initialize certification path checking for the offered certificates and revocation checks against CLRs
    CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
    PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
    rc.setOptions(EnumSet.of(
            PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
            PKIXRevocationChecker.Option.ONLY_END_ENTITY,
            PKIXRevocationChecker.Option.SOFT_FAIL, // handshake should not fail when CRL is not available
            PKIXRevocationChecker.Option.NO_FALLBACK)); // don't fall back to OCSP checking

    String keyStorePath = System.getProperty("javax.net.ssl.keyStore");
    if (keyStorePath == null) {
      String securityPath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator;
      if (Files.isRegularFile(Paths.get(securityPath + "jssecacerts")))
        keyStorePath = securityPath + "jssecacerts";
      else if (Files.isRegularFile(Paths.get(securityPath + "cacerts")))
        keyStorePath = securityPath + "cacerts";
    }
    String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword", "changeit");
    KeyStore ks = KeyStore.getInstance("JKS");
    TrustManagerUtil.loadKeyStore(ks, keyStorePassword, keyStorePath == null ? null : Paths.get(keyStorePath));

    PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ks, new X509CertSelector());
    pkixParams.addCertPathChecker(rc);

    tmf1.init(new CertPathTrustManagerParameters(pkixParams));

    javax.net.ssl.TrustManager[] tm1 = tmf1.getTrustManagers();
    if (tm1.length == 0)
      throw new IllegalStateException("No trust managers found");

    defaultTrustManagers.add((X509ExtendedTrustManager) tm1[0]);
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
        certAccepted = true;
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
        certAccepted = true;
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
        certAccepted = true;

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
    if(!certAccepted)
      tryCustomTrustManager(pChain, pE, pSimpleInfo);
  }

  private void tryCustomTrustManager(X509Certificate[] chain, CertificateException e, String pSimpleInfo)
      throws CertificateException
  {
    {
      X509Certificate certificate = chain[chain.length - 1];
      String alias = TrustManagerUtil.hashSHA1(certificate);
      if (trustStore.get(alias) != null)
        return;
      boolean persist = checkCertificateAndShouldPersist(chain, e, pSimpleInfo);
      trustStore.add(alias, certificate, persist);
    }
  }

  protected abstract boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
      throws CertificateException;
}