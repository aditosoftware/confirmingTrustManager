package de.adito.trustmanager.manager;

import de.adito.trustmanager.confirmingui.CertificateExceptionDetail;
import de.adito.trustmanager.store.ICustomTrustStore;
import de.adito.trustmanager.store.JKSCustomTrustStore;

import javax.net.ssl.*;
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

  /**
   * The constructor expects an Array of ICustomTrustStore. If this array is null or does not contain an entry, a NullPointerException
   * will be thrown.
   * The first trustStore in the array will be used to store the certificates trusted by the user
   * @param pTrustStores
   * @throws NoSuchAlgorithmException
   * @throws KeyStoreException
   * @throws IOException
   * @throws CertificateException
   * @throws InvalidAlgorithmParameterException
   */
  public CustomTrustManagerHandler(ICustomTrustStore[] pTrustStores) throws NoSuchAlgorithmException, KeyStoreException, IOException,
          CertificateException, InvalidAlgorithmParameterException {
    if(pTrustStores == null || pTrustStores.length == 0)
      throw new NullPointerException("Array is null");

      defaultTrustManagers = new ArrayList<>();
      acceptedCert = false;
      countHandledTMs = 0;

//decide on trustStore to safe certificates and initialize it as trustManager if it is a default one
    if(System.getProperty("javax.net.ssl.truststore") != null) {
        trustStore = new JKSCustomTrustStore(Paths.get(System.getProperty("javax.net.ssl.truststore")));
        defaultTrustManagers.add(new CustomTrustManager(trustStore).getTrustManager());
    }else
        trustStore = pTrustStores[0];

//initialize OS truststore
      X509ExtendedTrustManager trustManager = new CustomTrustManager(System.getProperty("os.name")).getTrustManager();
      if(trustManager != null)
        defaultTrustManagers.add(trustManager);

//initialize TrustManager with given truststores
      for (ICustomTrustStore pTrustStore : pTrustStores) {
          if (Files.isRegularFile(pTrustStore.getPath()))
              defaultTrustManagers.add(new CustomTrustManager(pTrustStore).getTrustManager());
      }

//initialize default trustManager
    defaultTrustManagers.add(new CustomTrustManager().getTrustManager());
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
   * @param pChain is a chain of X509Certificates
   * @param pException is a CertificateException
   * @param pSimpleInfo is the serverName, or null
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
   * @param pChain is a chain of X509Certificates
   * @param pException is a CertificateException
   * @param pSimpleInfo is the serverName, or null
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