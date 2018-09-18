package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.CertificateExceptionDetail;
import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.*;
import java.net.Socket;
import java.security.cert.*;
import java.util.*;

/**
 * This class initiates a list of TrustManagers to test if the certificate is already trusted by any of these TMs. If it
 * is not trusted, the certificateException will be caught and the JDialog will be prompted.
 * The Java trustManager or a trustManager with a keystore set by the systemProperties will be used as default.
 * All trustManagers are initialised to throw a certificateRevokedException.
 */
public abstract class CustomTrustManager extends X509ExtendedTrustManager
{
    private final List<X509ExtendedTrustManager> defaultTrustManagers;
    private ICustomTrustStore trustStore;
    private boolean acceptedCert;
    private int countHandledTMs;
    
    /**
     * The constructor will throw a nullPointerException if it has no trustStore to safe the trusted certificates and if
     * there is no trustManager to validate the certificate with.
     */
    public CustomTrustManager(ICustomTrustStore pTrustStore, Iterable<X509ExtendedTrustManager> pTrustManagers)
    {
        if (pTrustStore == null)
            throw new NullPointerException("trustStore is null");
        trustStore = pTrustStore;
        
        defaultTrustManagers = new ArrayList<>();
        for (X509ExtendedTrustManager pTrustManager : pTrustManagers)
            defaultTrustManagers.add(pTrustManager);
        
        if (defaultTrustManagers.isEmpty())
            throw new NullPointerException("no trustManager found");
        
        acceptedCert = false;
        countHandledTMs = 0;
    }

    public X509Certificate[] getAcceptedIssuers()
    {
        List<X509Certificate> certificates = new LinkedList<>();
        for (X509ExtendedTrustManager trustManager : defaultTrustManagers)
        {
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
        for (X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers)
        {
            try
            {
                defaultTrustManager.checkServerTrusted(pChain, pAuthType);
                acceptedCert = true;
                
            } catch (CertificateException e)
            {
                _handleCertificateException(pChain, e, null);
            }
        }
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] pChain, String pAuthType, Socket pSocket) throws CertificateException
    {
        for (X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers)
        {
            try
            {
                defaultTrustManager.checkServerTrusted(pChain, pAuthType, pSocket);
                acceptedCert = true;
                
            } catch (CertificateException e)
            {
                _handleCertificateException(pChain, e, pSocket.getInetAddress().getHostName());
            }
        }
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] pChain, String pAuthType, SSLEngine pSSLEngine) throws CertificateException
    {
        for (X509ExtendedTrustManager defaultTrustManager : defaultTrustManagers)
        {
            try
            {
                defaultTrustManager.checkServerTrusted(pChain, pAuthType, pSSLEngine);
                acceptedCert = true;
                
            } catch (CertificateException e)
            {
                _handleCertificateException(pChain, e, pSSLEngine.getPeerHost());
            }
        }
    }
    
    /**
     * In case of a certificateException, the other trustManagers will be tested for untrustedRoot and selfSigned. Otherwise
     * the JDialog will be prompted.
     */
    private void _handleCertificateException(X509Certificate[] pChain, CertificateException pException, String pSimpleInfo) throws CertificateException
    {
        if (pChain == null || pChain.length == 0)
            throw pException;
        Throwable cause = pException.getCause();
        if (cause instanceof CertPathValidatorException)
        {
            Throwable rootCause = cause.getCause();
            if (rootCause instanceof CertificateRevokedException)
                throw pException;
        }
        //get the type of the thrown exception to determine behaviour -> go to exceptionDialog or test the other trustManagers
        List<CertificateExceptionDetail.EType> list = CertificateExceptionDetail.createExceptionDetail(pChain, pException, pSimpleInfo).getTypes();
        
        if (defaultTrustManagers.size() != 1 && list.size() == 1 && (list.contains(CertificateExceptionDetail.EType.UNTRUSTED_ROOT) ||
                list.contains(CertificateExceptionDetail.EType.SELF_SIGNED)))
        {
            if (acceptedCert)//if there is more than one trustManager, but one already recognized the certificate
                return;
            
            if (countHandledTMs < defaultTrustManagers.size() - 1)
            {//keep track of number of already tested trustManagers. if all don't accept the cert, the exceptionDialog will appear
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
     * This method will use the user's decision and add the certificate permanently or only trust it once.
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