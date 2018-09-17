package de.adito.trustmanager;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Test_TrustManagerBuilder
{
    
    @Before
    public void resetSystemProperties()
    {
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStoreType");
    }
    
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
        System.setProperty("javax.net.ssl.trustStore", "NUL");
        System.setProperty("javax.net.ssl.trustStoreType", "Windows-ROOT");
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildDefaultTrustManager();
        Assert.assertNotNull("TrustManager with SystemProperties was not created", trustManager);
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
