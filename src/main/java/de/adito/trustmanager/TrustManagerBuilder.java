package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.*;
import de.adito.trustmanager.store.*;

import javax.net.ssl.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * This class can provide different trustManager: JavaTM, operatingSystemTM, customTM
 */

public class TrustManagerBuilder
{

    private TrustManagerBuilder()
    {
    }

    public static TrustManager buildConfirmingTrustManager(boolean pAllowDialog) throws CertificateException,
        InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        return buildConfirmingTrustManager(new JKSCustomTrustStore(), pAllowDialog);
    }

    public static TrustManager buildConfirmingTrustManager(ICustomTrustStore pTrustStore, boolean pAllowDialog)
        throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        if (pAllowDialog)
            return new ConfirmingUITrustManager(pTrustStore, createDefaultTrustManagers());
        else
            return new NoConfirmingTrustManager(pTrustStore, createDefaultTrustManagers());
    }

    /**
     * A method to create all default TrustManagers.
     */
    public static List<X509ExtendedTrustManager> createDefaultTrustManagers()
        throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidAlgorithmParameterException
    {
        List<X509ExtendedTrustManager> tms = new ArrayList<>();

        //initialize OS trustManager
        X509ExtendedTrustManager trustManager = buildOsTrustManager(System.getProperty("os.name"));
        if (trustManager != null)
            tms.add(trustManager);

        //initialize default trustManager
        tms.add(buildJavaTrustManager());

        return tms;
    }

    public static X509ExtendedTrustManager buildJavaTrustManager()
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException
    {
        String trustStorePath = System.getProperty("javax.net.ssl.trustStore");
        if (trustStorePath == null)
        {
            String securityPath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator;
            if (Files.isRegularFile(Paths.get(securityPath + "jssecacerts")))
                trustStorePath = securityPath + "jssecacerts";
            else if (Files.isRegularFile(Paths.get(securityPath + "cacerts")))
                trustStorePath = securityPath + "cacerts";
        }
        String keyStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "changeit");
        KeyStore jKSKeyStore = TrustManagerUtil.loadKeyStore(keyStorePassword, trustStorePath == null ? null : Paths.get(trustStorePath));

        return buildTrustManager(jKSKeyStore);
    }

    /**
     * This will make a trustManager depending on the operatingSystem. If the operatingSystem is not supported, null will be returned.
     * {@link CustomTrustManager} will ignore null TMs.
     *
     * @param pOsName operating system name
     */
    public static X509ExtendedTrustManager buildOsTrustManager(String pOsName)
            throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, InvalidAlgorithmParameterException
    {
        KeyManagerFactory osKeyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        if (pOsName.startsWith("Windows")) {
            KeyStore osKeyStore= KeyStore.getInstance("Windows-ROOT");

            osKeyStore.load(null, null);  //default truststore is used.
            try {
                osKeyManagerFactory.init(osKeyStore, null);
            }
            catch (UnrecoverableKeyException e) {
                e.printStackTrace();
                return null;
            }

            return buildTrustManager(osKeyStore);
        }
        return null;
    }

  public static X509ExtendedTrustManager buildTrustManager(KeyStore pKeyStore)
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
