package de.adito.trustmanager;

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
 * This class can provide different trustManager: JavaTM, operatingSystemTM, customTM
 */

public class TrustManagerBuilder
{
    
    private TrustManagerBuilder()
    {
    }
    
    public static X509ExtendedTrustManager buildDefaultTrustManager()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException
    {
        String javaKeyStorePath = System.getProperty("javax.net.ssl.keyStore");
        if (javaKeyStorePath == null)
        {
            String securityPath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator;
            if (Files.isRegularFile(Paths.get(securityPath + "jssecacerts")))
                javaKeyStorePath = securityPath + "jssecacerts";
            else if (Files.isRegularFile(Paths.get(securityPath + "cacerts")))
                javaKeyStorePath = securityPath + "cacerts";
        }
        String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword", "changeit");
        KeyStore jKSKeyStore = TrustManagerUtil.loadKeyStore(keyStorePassword, javaKeyStorePath == null ? null : Paths.get(javaKeyStorePath));
        
        return buildDefaultTrustManager(jKSKeyStore);
    }
    
    public static X509ExtendedTrustManager buildDefaultTrustManager(KeyStore pKeyStore)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException
    {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        
        PKIXBuilderParameters tsPkixParams = _createRevocationChecker(pKeyStore);
        trustManagerFactory.init(new CertPathTrustManagerParameters(tsPkixParams));
        javax.net.ssl.TrustManager[] tsTM = trustManagerFactory.getTrustManagers();
        if (tsTM.length == 0)
            throw new IllegalStateException("No trust managers found");
        
        return (X509ExtendedTrustManager) tsTM[0];
    }
    
    /**
     * This will make a trustManager depending on the operatingSystem. If the operatingSystem is not supported, null will be returned.
     * {@link CustomTrustManager} will ignore null TMs.
     *
     * @param pOsName operating system name
     */
    public static X509ExtendedTrustManager buildOSTrustStore(String pOsName)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, InvalidAlgorithmParameterException
    {
        KeyManagerFactory osKeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        
        KeyStore osKeyStore;
        if (pOsName.startsWith("Windows"))
            osKeyStore = KeyStore.getInstance("Windows-ROOT");
        else
            osKeyStore = null;
        
        if (osKeyStore != null)
        {
            osKeyStore.load(null, null);  //default truststore is used.
            try
            {
                osKeyManagerFactory.init(osKeyStore, null);
            } catch (UnrecoverableKeyException e)
            {
                e.printStackTrace();
            }
            
            return buildDefaultTrustManager(osKeyStore);
        }
        return null;
    }
    
    /**
     * The KeyStore gets enabled to detect a revoked certificate.
     */
    private static PKIXBuilderParameters _createRevocationChecker(KeyStore pKeyStore)
            throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException
    {
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
}
