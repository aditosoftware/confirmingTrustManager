package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;
import sun.security.validator.ValidatorException;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.EnumSet;

public abstract class CustomTrustManager implements X509TrustManager {
    private final X509TrustManager defaultTrustManager;
    private ICustomTrustStore trustStore;


    public CustomTrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, KeyStoreException, IOException,
            CertificateException, InvalidAlgorithmParameterException {
        trustStore = pTrustStore;

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

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

        tmf.init(new CertPathTrustManagerParameters(pkixParams));

        javax.net.ssl.TrustManager[] tm = tmf.getTrustManagers();
        if (tm.length == 0)
            throw new IllegalStateException("No trust managers found");
        defaultTrustManager = (X509TrustManager) tm[0];
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        throw new UnsupportedOperationException("checkClientTrusted");
    }

    public X509Certificate[] getAcceptedIssuers() {
        return defaultTrustManager.getAcceptedIssuers();
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        try {
            defaultTrustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            if (chain == null || chain.length == 0)
                throw e;
            if (e instanceof ValidatorException) {
                Throwable cause = e.getCause();
                if (cause instanceof CertPathValidatorException) {
                    Throwable rootCause = cause.getCause();
                    if (rootCause instanceof CertificateExpiredException || rootCause instanceof CertificateRevokedException)
                        throw e;
                }
            }
            tryCustomTrustManager(chain, e);
        }
    }

    private void tryCustomTrustManager(X509Certificate[] chain, CertificateException e)
            throws CertificateException {
        {
            X509Certificate certificate = chain[chain.length - 1];
            String alias = TrustManagerUtil.hashSHA1(certificate);
            if (trustStore.get(alias) != null)
                return;
            promptForCertificate(chain, e);
            trustStore.add(alias, certificate);
        }
    }

    protected abstract void promptForCertificate(X509Certificate[] pChain, CertificateException pE)
            throws CertificateException;

}