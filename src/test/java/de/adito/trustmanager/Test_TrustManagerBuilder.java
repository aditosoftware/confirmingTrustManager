package de.adito.trustmanager;

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Test_TrustManagerBuilder
{
    @Test
    public void testBuildDefaultJavaTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildDefaultTrustManager();
        Assert.assertNotNull("Default TrustManager was not created", trustManager);
    }
    
    @Test
    public void testBuildDefaultTrustManagerSystemProperties()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        System.setProperty("javax.net.ssl.keyStore", (System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts"));
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildDefaultTrustManager();
        
        Assert.assertNotNull("TrustManager with SystemProperties was not created", trustManager);
        System.clearProperty("javax.net.ssl.keyStore");
    }
    
    @Test
    public void testOSTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildOSTrustStore(System.getProperty("os.name"));
        Assert.assertNotNull("An operating system specific trustManager was not created, you might have to include " +
                "logic in TrustManagerBuilder.buildOSTrustStore()\n", trustManager);
    }
    
    @Test
    public void testNoOSTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildOSTrustStore("NotValidOS");
        Assert.assertNull("Expected null as the operating system 'NotValidOS' should not be recognised", trustManager);
    }
}
