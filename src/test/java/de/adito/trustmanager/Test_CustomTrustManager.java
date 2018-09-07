package de.adito.trustmanager;

import de.adito.trustmanager.store.ICustomTrustStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.net.ssl.X509ExtendedTrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import static org.junit.Assert.fail;

public class Test_CustomTrustManager
{
    @BeforeAll
    public static void setUp(){
        System.clearProperty("javax.net.ssl.trustStore");
    }
    
    @Test
    public void testConstructorTrustStoreNull(){
        Iterable<X509ExtendedTrustManager> iterableMock = Mockito.mock(Iterable.class);
        try
        {
            new CustomTrustManager(null, iterableMock)
            {
                @Override
                protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) {
                    return false;
                }
            };
            fail("Expected NullPointerException");
        }catch(NullPointerException exc) {}
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
                protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) throws CertificateException {
                    return false;
                }
            };
            fail("Expected NullPointerException");
        }catch(NullPointerException exc){}
    }
    
    @Test
    public void testConstructorEmptyIterable()
    {
        ICustomTrustStore trustStoreMock = Mockito.mock(ICustomTrustStore.class);
        
        try
        {
            new CustomTrustManager(trustStoreMock, new ArrayList<>()) {
                @Override
                protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) throws CertificateException {
                    return false;
                }
            };
            fail("Expected NullPointerException");
            
        }catch(NullPointerException exc){}

    }
}
