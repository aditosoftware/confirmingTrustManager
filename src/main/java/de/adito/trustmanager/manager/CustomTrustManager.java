package de.adito.trustmanager.manager;

import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.EnumSet;

/**
 * This class can provide different trustManager: JavaTM, OStM, customTM with truststore from eg userInput
 */

public class CustomTrustManager {
    private X509ExtendedTrustManager trustManager;

    /**
     * This trustManager will use the JavaKeyStore
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidAlgorithmParameterException
     */
    public CustomTrustManager() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

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

        PKIXBuilderParameters javaPkixParams = _createRevocationChecker(JKSKeyStore);
        trustManagerFactory.init(new CertPathTrustManagerParameters(javaPkixParams));
        javax.net.ssl.TrustManager[] javaTM= trustManagerFactory.getTrustManagers();
        if (javaTM.length == 0)
            throw new IllegalStateException("No trust managers found");
        trustManager = (X509ExtendedTrustManager) javaTM[0];
    }

    /**
     * This will make a trustManager with a given trustStore, eg from userInput
     * @param pTrustStore
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     */
    public CustomTrustManager(ICustomTrustStore pTrustStore) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        PKIXBuilderParameters tsPkixParams = _createRevocationChecker(pTrustStore.getKs());
        trustManagerFactory.init(new CertPathTrustManagerParameters(tsPkixParams));
        javax.net.ssl.TrustManager[] tsTM = trustManagerFactory.getTrustManagers();
        if (tsTM.length == 0)
            throw new IllegalStateException("No trust managers found");

        trustManager = (X509ExtendedTrustManager) tsTM[0];
    }

    /**
     * This will make a trustManager depending on its operatingSystem. If the operatingSystem is not supported, this will return null
     * and it will not be added to the trustManagerList in CustomTrustManagerHandler
     * @param pOsName
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     */
    public CustomTrustManager(String pOsName) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, InvalidAlgorithmParameterException {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyManagerFactory osKeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        KeyStore osKeyStore;
        if (pOsName.startsWith("Windows")) {
            osKeyStore = KeyStore.getInstance("Windows-ROOT");
        } else if (pOsName.startsWith("Mac")) {   //this code snippet needs to be tested with a macOS
            try {
                osKeyStore = KeyStore.getInstance("KeychainStore", "Apple");
            } catch (NoSuchProviderException e) {
                osKeyStore = null;
            }
        } else {
            osKeyStore = null;
        }

        if (osKeyStore != null) {
            osKeyStore.load(null, null);  //default truststore is used.
            try {
                osKeyManagerFactory.init(osKeyStore, null);
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            }

            PKIXBuilderParameters osPkixParams = _createRevocationChecker(osKeyStore);
            trustManagerFactory.init(new CertPathTrustManagerParameters(osPkixParams));
            javax.net.ssl.TrustManager[] osTM = trustManagerFactory.getTrustManagers();
            if (osTM.length == 0)
                throw new IllegalStateException("No trust managers found");
            trustManager = (X509ExtendedTrustManager) osTM[0];

        } else{
            trustManager = null;
        }

    }

    /**
     * This method enables the KeyStore to detect a revokedCertificate
     * @param pKeyStore
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidAlgorithmParameterException
     */
    private PKIXBuilderParameters _createRevocationChecker(KeyStore pKeyStore) throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
        revocationChecker.setOptions(EnumSet.of(
                PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
                PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                PKIXRevocationChecker.Option.SOFT_FAIL, // handshake should not fail when CRL is not available
                PKIXRevocationChecker.Option.NO_FALLBACK)); // don't fall back to OCSP checking

        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(pKeyStore, new X509CertSelector());
        pkixParams.addCertPathChecker(revocationChecker);

        return pkixParams;
    }

    public X509ExtendedTrustManager getTrustManager(){
        return trustManager;
    }
}
