package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.net.ssl.X509ExtendedTrustManager;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import static org.junit.Assert.*;

public class Test_InitializeCustomTrustManager
{
    @BeforeEach
    public void setUp()
    {
        System.clearProperty("javax.net.ssl.trustStore");
    }
    
    //Test Constructor
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
    
    //other tests
    @Test
    public void testCreateStandardTrustManagersNotEmpty()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        ArrayList<X509ExtendedTrustManager> tms = (ArrayList<X509ExtendedTrustManager>) CustomTrustManager.createStandardTrustManagers();
        assertTrue("TrustManagerList cannot be empty", !tms.isEmpty());
    }
    
    @Test
    public void testCreateStandardTrustManagers()
            throws CertificateException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, KeyStoreException, IOException
    {
        String path = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
        System.setProperty("javax.net.ssl.truststore", path);
        ArrayList<X509ExtendedTrustManager> tms = (ArrayList<X509ExtendedTrustManager>) CustomTrustManager.createStandardTrustManagers();
        
        if (System.getProperty("os.name").contains("Windows"))
            assertEquals("Expected three trustManagers", 3, tms.size());
            //for not implemented Operating Systems
        else
            assertEquals("Expected two trustManagers", 2, tms.size());
    }
}
