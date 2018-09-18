package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.ConfirmingUITrustManager;
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

import static org.junit.Assert.fail;

public class Test_InitializeCustomTrustManager
{
    //Test CustomTrustManagerConstructor
    @Test
    public void testConstructorTrustStoreNull()
    {
        Iterable iterableMock = Mockito.mock(Iterable.class);
        try
        {
            new CustomTrustManager(null, iterableMock)
            {
                @Override
                protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
                {
                    return false;
                }
            };
            fail("Expected NullPointerException");
        } catch (NullPointerException exc)
        {
        }
    }
    
    @Test
    public void testCreateSslContextTrustStoreNull()
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, InvalidAlgorithmParameterException, IOException
    {
        try
        {
            ConfirmingUITrustManager.createSslContext(null);
            fail("Expected NullPointerException");
        } catch (NullPointerException exc)
        {
        }
    }
    
    @Test
    public void testConstructorIterableNull()
    {
        ICustomTrustStore trustStoreMock = Mockito.mock(ICustomTrustStore.class);
        try
        {
            new CustomTrustManager(trustStoreMock, null)
            {
                @Override
                protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
                {
                    return false;
                }
            };
            fail("Expected NullPointerException");
        } catch (NullPointerException exc)
        {
        }
    }
    
    @Test
    public void testConstructorEmptyIterable()
    {
        ICustomTrustStore trustStoreMock = Mockito.mock(ICustomTrustStore.class);
        try
        {
            new CustomTrustManager(trustStoreMock, new ArrayList<>())
            {
                @Override
                protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
                {
                    return false;
                    
                }
            };
            fail("Expected NullPointerException");
            
        } catch (NullPointerException exc)
        {
        }
    }
    
    @Test
    public void testCreateStandardTrustManagersNotEmpty()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        ArrayList<X509ExtendedTrustManager> tms = (ArrayList<X509ExtendedTrustManager>) CustomTrustManager.createStandardTrustManagers();
        Assert.assertTrue("TrustManagerList cannot be empty", !tms.isEmpty());
    }
    
    @Test
    public void testCreateStandardTrustManagers()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        String path = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
        System.setProperty("javax.net.ssl.truststore", path);
        ArrayList<X509ExtendedTrustManager> tms = (ArrayList<X509ExtendedTrustManager>) CustomTrustManager.createStandardTrustManagers();
        System.clearProperty("javax.net.ssl.truststore");
        
        if (System.getProperty("os.name").contains("Windows"))
            Assert.assertEquals("Expected three trustManagers", 3, tms.size());
            //for not implemented Operating Systems, if this fails, maybe a new test for another OS needs to be implemented
        else
            Assert.assertEquals( "Expected two trustManagers", 2, tms.size());
    }
}
