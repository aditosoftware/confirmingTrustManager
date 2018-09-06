package de.adito.trustmanager;

import org.junit.jupiter.api.AfterEach;
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

    @Test
    public void testBuildDefaultJavaTrustManager()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildDefaultTrustManager();
        assertNotNull(trustManager);
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    public void testBuildDefaultTrustManagerSystemProperties() throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException {
        System.setProperty("javax.net.ssl.trustStore", "NUL");
        System.setProperty("javax.net.ssl.trustStoreType", "Windows-ROOT");
        X509ExtendedTrustManager trustManager = TrustManagerBuilder.buildDefaultTrustManager();
        assertNotNull(trustManager);
    }

    @AfterEach
    public void resetSystemProperties(){
        System.clearProperty("javax.net.ssl.trustStore");
        System.clearProperty("javax.net.ssl.trustStoreType");
    }
}
