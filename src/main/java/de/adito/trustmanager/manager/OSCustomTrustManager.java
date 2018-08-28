package de.adito.trustmanager.manager;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.EnumSet;

public class OSCustomTrustManager extends CustomTrustManager {

    X509ExtendedTrustManager trustManager;

    public OSCustomTrustManager() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, InvalidAlgorithmParameterException {
        String osName = System.getProperty("os.name");

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyManagerFactory osKeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore osKeyStore;
        if (osName.startsWith("Windows")) {
            osKeyStore = KeyStore.getInstance("Windows-ROOT");
        } else if (osName.startsWith("Mac")) {   //this code snippet needs to be tested with a macOS
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

            // initialize certification path checking for the offered certificates and revocation checks against CLRs
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
            revocationChecker.setOptions(EnumSet.of(
                    PKIXRevocationChecker.Option.PREFER_CRLS, // prefer CLR over OCSP
                    PKIXRevocationChecker.Option.ONLY_END_ENTITY,
                    PKIXRevocationChecker.Option.SOFT_FAIL, // handshake should not fail when CRL is not available
                    PKIXRevocationChecker.Option.NO_FALLBACK)); // don't fall back to OCSP checking

            PKIXBuilderParameters osPkixParams = new PKIXBuilderParameters(osKeyStore, new X509CertSelector());
            osPkixParams.addCertPathChecker(revocationChecker);
            trustManagerFactory.init(new CertPathTrustManagerParameters(osPkixParams));
            javax.net.ssl.TrustManager[] osTM = trustManagerFactory.getTrustManagers();
            if (osTM.length == 0)
                throw new IllegalStateException("No trust managers found");
            trustManager = (X509ExtendedTrustManager) osTM[0];
        }

    }

    public X509ExtendedTrustManager getTrustManager(){
        return trustManager;
    }

}
