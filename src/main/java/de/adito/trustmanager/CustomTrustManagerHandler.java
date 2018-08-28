package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.CertificateExceptionDetail;
import de.adito.trustmanager.manager.OSCustomTrustManager;
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

/**
 * This class initiates a list of TrustManagers to test if the Certificate is already trusted by any of these TMs. If it
 * is not trusted, the certificateException will be caught and the JDialog to decide what to do will be prompted.
 * The Java trustManager will be used as default.
 * All trustManagers are initialised to throw a certificateRevokedException in case of a revoked certificate
 */

public abstract class CustomTrustManagerHandler extends X509ExtendedTrustManager
{
  private final List<X509ExtendedTrustManager> defaultTrustManagers;
  private ICustomTrustStore trustStore;
  private boolean acceptedCert;
  private int countHandledTMs;

  public CustomTrustManagerHandler(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException, IOException,
          CertificateException, InvalidAlgorithmParameterException {
    defaultTrustManagers = new ArrayList<>();
    trustStore = pTrustStore;

    String osName = System.getProperty("os.name");
    acceptedCert = false;
    countHandledTMs = 0;

    // initialize certification path checking for the offered certificates and revocation checks against CLRs
    CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
    PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
    revocationChecker.setOptions(EnumSet.of(
            PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
            PKIXRevocationChecker.Option.ONLY_END_ENTITY,
            PKIXRevocationChecker.Option.SOFT_FAIL, // handshake should not fail when CRL is not available
            PKIXRevocationChecker.Option.NO_FALLBACK)); // don't fall back to OCSP checking
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

    defaultTrustManagers.add(new OSCustomTrustManager().getTrustManager());

//initialize TrustManager with given truststore
      if(false) {       // only to not throw exception cause trustmanager.jks does not exist atm
          PKIXBuilderParameters tsPkixParams = new PKIXBuilderParameters(trustStore.getKs(), new X509CertSelector());
          tsPkixParams.addCertPathChecker(revocationChecker);
          trustManagerFactory.init(new CertPathTrustManagerParameters(tsPkixParams));
          javax.net.ssl.TrustManager[] tsTM = trustManagerFactory.getTrustManagers();
          if (tsTM.length == 0)
              throw new IllegalStateException("No trust managers found");

          defaultTrustManagers.add((X509ExtendedTrustManager) tsTM[0]);
      }
//initialize default trustManager
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
    if (javaTM.length == 0)
      throw new IllegalStateException("No trust managers found");

    defaultTrustManagers.add((X509ExtendedTrustManager) javaTM[0]);
  }

  public X509Certificate[] getAcceptedIssuers() {
    List<X509Certificate> certificates = new LinkedList<>();
    for (X509ExtendedTrustManager trustManager : defaultTrustManagers) {
      certificates.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
    }
    return certificates.toArray(new X509Certificate[0]);
  }

  public void checkClientTrusted(X509Certificate[] pChain, String pAuthType)
  {
    throw new UnsupportedOperationException("checkClientTrusted");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] pChain, String pAuthType, Socket pSocket)
  {
    throw new UnsupportedOperationException("checkClientTrusted");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] pChain, String pAuthType, SSLEngine pSSLEngine)
  {
    throw new UnsupportedOperationException("checkClientTrusted");
  }

  public void checkServerTrusted(X509Certificate[] pChain, String pAuthType) throws CertificateException
  {
    for(X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers) {
      try {
        defaultTrustManager.checkServerTrusted(pChain, pAuthType);
        acceptedCert = true;

      } catch (CertificateException e) {
        _handleCertificateException(pChain, e, null);
      }
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] pChain, String pAuthType, Socket pSocket) throws CertificateException
  {
    for(X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers) {
      try {
        defaultTrustManager.checkServerTrusted(pChain, pAuthType, pSocket);
        acceptedCert = true;

      } catch (CertificateException e) {
        _handleCertificateException(pChain, e, pSocket.getInetAddress().getHostName());
      }
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] pChain, String pAuthType, SSLEngine pSSLEngine) throws CertificateException
  {
    for(X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers) {
      try {
        defaultTrustManager.checkServerTrusted(pChain, pAuthType, pSSLEngine);
        acceptedCert = true;

      } catch (CertificateException e) {
        _handleCertificateException(pChain, e, pSSLEngine.getPeerHost());
      }
    }
  }

  /**
   * This method first checks for a certificateRevokedException. Furthermore it will check the other trustManagers in the
   * list, if the exception is 'untrustedRoot' or 'selfsigned'. If one of the trustManagers recognises the certificate, the
   * certificate will be trusted. Otherwise 'countHandledTMs' and 'acceptedCert' will be reseted in case of another
   * certificate check.
   * @param pChain
   * @param pException
   * @param pSimpleInfo
   * @throws CertificateException
   */
  private void _handleCertificateException(X509Certificate[] pChain, CertificateException pException, String pSimpleInfo) throws CertificateException
  {
    if (pChain == null || pChain.length == 0)
      throw pException;
    Throwable cause = pException.getCause();
    if (cause instanceof CertPathValidatorException) {
      Throwable rootCause = cause.getCause();
      if (rootCause instanceof CertificateRevokedException)
        throw pException;
    }
    //get the type of the thrown exception to determine behaviour -> go to exceptionDialog or test the other trustManagers
    ArrayList<CertificateExceptionDetail.EType> list = CertificateExceptionDetail.createExceptionDetail(pChain, pException, pSimpleInfo).getTypeArray();

    if(defaultTrustManagers.size() != 1 && list.size() == 1 && (list.contains(CertificateExceptionDetail.EType.UNTRUSTED_ROOT) ||
            list.contains(CertificateExceptionDetail.EType.SELF_SIGNED))) {
        if (acceptedCert){//if there is more than one trustManager, but one already recognized the certificate
            return;
        }
        if(countHandledTMs < defaultTrustManagers.size() - 1){//keep track of number of already tested trustManagers. if all don't accept the cert, the exceptionDialog will appear
            countHandledTMs++;
            return;
        }
    }
    //reset counter and acceptedCert in case there are other servers tested later
    countHandledTMs = 0;
    acceptedCert = false;
    _tryCustomTrustManager(pChain, pException, pSimpleInfo);
  }

  /**
   * This method will use the decision of the user and add the certificate permanently or only trust it once
   * @param pChain
   * @param pException
   * @param pSimpleInfo
   * @throws CertificateException
   */
  private void _tryCustomTrustManager(X509Certificate[] pChain, CertificateException pException, String pSimpleInfo)
      throws CertificateException
  {
    {
      X509Certificate certificate = pChain[pChain.length - 1];
      String alias = TrustManagerUtil.hashSHA1(certificate);
      if (trustStore.get(alias) != null)
        return;
      boolean persist = checkCertificateAndShouldPersist(pChain, pException, pSimpleInfo);
      trustStore.add(alias, certificate, persist);
    }
  }

  protected abstract boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
      throws CertificateException;
}