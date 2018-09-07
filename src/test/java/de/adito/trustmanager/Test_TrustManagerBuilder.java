package de.adito.trustmanager;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class Test_TrustManagerBuilder {

    @BeforeEach
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
        assertNotNull(trustManager, "Default TrustManager was not created");
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    public void testBuildDefaultTrustManagerSystemProperties()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        System.setProperty("javax.net.ssl.trustStore", "NUL");
        System.setProperty("javax.net.ssl.trustStoreType", "Windows-ROOT");
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildDefaultTrustManager();
        assertNotNull(trustManager, "TrustManager with SystemProperties was not created");
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    public void testWindowsTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildOSTrustStore(System.getProperty("os.name"));
         assertNotNull(trustManager, "WindowsTrustManager was not created");
    }

    @Test
    @EnabledOnOs(OS.MAC)
    public void testMacTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildOSTrustStore(System.getProperty("os.name"));
        assertNotNull(trustManager, "MacTrustManager was not created");
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    public void testLinuxTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildOSTrustStore(System.getProperty("os.name"));
        assertNotNull(trustManager, "LinuxTrustManager was not created");
    }
}
