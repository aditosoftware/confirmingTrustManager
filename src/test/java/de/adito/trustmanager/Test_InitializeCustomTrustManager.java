package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;
import org.junit.*;
import org.mockito.Mockito;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class Test_InitializeCustomTrustManager
{
    @Test(expected = NullPointerException.class)
    public void testConstructorTrustStoreNull()
    {
        Iterable<X509ExtendedTrustManager> iterableMock = Mockito.mock(Iterable.class);
        new CustomTrustManager(null, iterableMock)
        {
            @Override
            protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
            {
                return false;
            }
        };
    }

    @Test(expected = NullPointerException.class)
    public void testCreateSslContextTrustStoreNull()
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, InvalidAlgorithmParameterException, IOException
    {
        TrustManagerSslContext.initSslContext((ICustomTrustStore)null);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorIterableNull()
    {
        ICustomTrustStore trustStoreMock = Mockito.mock(ICustomTrustStore.class);
        new CustomTrustManager(trustStoreMock, null)
        {
            @Override
            protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
            {
                return false;
            }
        };
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorEmptyIterable()
    {
        ICustomTrustStore trustStoreMock = Mockito.mock(ICustomTrustStore.class);
        new CustomTrustManager(trustStoreMock, new ArrayList<>())
        {
            @Override
            protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
            {
                return false;
            }
        };
    }

    @Test
    public void testCreateStandardTrustManagersNotEmpty()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        ArrayList<X509ExtendedTrustManager> tms = (ArrayList<X509ExtendedTrustManager>) TrustManagerBuilder.createDefaultTrustManagers();
        Assert.assertFalse("TrustManagerList cannot be empty", tms.isEmpty());
    }

    @Test
    public void testCreateStandardTrustManagers()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        String path = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
        System.setProperty("javax.net.ssl.truststore", path);
        ArrayList<X509ExtendedTrustManager> tms = (ArrayList<X509ExtendedTrustManager>) TrustManagerBuilder.createDefaultTrustManagers();
        System.clearProperty("javax.net.ssl.truststore");

        if (System.getProperty("os.name").contains("Windows"))
            Assert.assertEquals("Expected three trustManagers", 3, tms.size());
            //for not implemented Operating Systems, if this fails, maybe a new test for another OS needs to be implemented
        else
            Assert.assertEquals( "Expected two trustManagers", 2, tms.size());
    }
}
