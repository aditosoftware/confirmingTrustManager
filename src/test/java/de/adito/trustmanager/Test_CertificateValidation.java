package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.CertificateExceptionDetail;
import de.adito.trustmanager.store.ICustomTrustStore;
import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class Test_CertificateValidation
{
    private static CertificateExceptionDetail.EType[] resultETypes;
    private static String resultString;
    private static CertificateExceptionDetail.EType[] resultWrongHost;
    private static Path path;
    private static X509Certificate[] chain;
    
    @BeforeClass
    public static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException
    {
        path = Paths.get(System.getProperty("user.dir") + File.separator + "testTrustStore.jks");
        resultString = null;
        resultWrongHost = null;
        ICustomTrustStore trustStore = new JKSCustomTrustStore(path);
        CustomTrustManager trustManager = new CustomTrustManager(trustStore, TrustManagerBuilder.createDefaultTrustManagers())
        {
            @Override
            protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
                    throws CertificateException
            {
                chain = pChain;
                CertificateExceptionDetail exceptionDetail = CertificateExceptionDetail.createExceptionDetail(pChain, pE, pSimpleInfo);
                resultETypes = exceptionDetail.getTypes().toArray(new CertificateExceptionDetail.EType[0]);
                
                if (resultETypes[0] == CertificateExceptionDetail.EType.WRONG_HOST)
                {
                    resultWrongHost = resultETypes;
                    resultString = exceptionDetail.makeExceptionMessage(pSimpleInfo);
                }
                return false;
            }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());
        SSLContext.setDefault(sslContext);
    }
    
    @Before
    public void resetResult()
    {
        resultETypes = null;
    }
    
    @Test
    public void testExpired() throws IOException
    {
        _read(new URL("https://expired.badssl.com/"));
        assertArrayEquals("CertificateExceptionDetail returned wrong EType",
                new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }
    
    @Test
    public void testWrongHost() throws IOException
    {
        _read(new URL("https://wrong.host.badssl.com/"));
        if (resultETypes == null)
            resultETypes = resultWrongHost;
        
        if (resultETypes.length == 1)
            assertArrayEquals("CertificateExceptionDetail returned wrong EType",
                    new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST}, resultETypes);
        else
            assertArrayEquals("CertificateExceptionDetail returned wrong ETypes",
                    new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST,
                    CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }
    
    @Test
    public void testSelfSigned() throws IOException
    {
        _read(new URL("https://self-signed.badssl.com"));
        if (resultETypes.length == 1)
            assertArrayEquals("CertificateExceptionDetail returned wrong EType",
                    new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED}, resultETypes);
        else
            assertArrayEquals("CertificateExceptionDetail returned wrong ETypes",
                    new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED,
                    CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }
    
    @Test
    public void testUntrustedRoot() throws IOException
    {
        _read(new URL("https://untrusted-root.badssl.com/"));
        if (resultETypes.length == 1)
            assertArrayEquals("CertificateExceptionDetail returned wrong EType",
                    new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT}, resultETypes);
        else
            assertArrayEquals("CertificateExceptionDetail returned wrong ETypes",
                    new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT,
                    CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }
    
    @Test
    public void testRevoked()
    {
        try
        {
            _read(new URL("https://revoked.badssl.com/"));
            fail("Expected CertificateRevokedException, but no exception was thrown");
        } catch (Exception exc)
        {
            Throwable cause = exc.getCause();
            if (cause.getClass().getSimpleName().equals("ValidatorException"))
            {
                Throwable secondCause = cause.getCause();
                if (secondCause instanceof CertPathValidatorException)
                {
                    Throwable rootCause = secondCause.getCause();
                    assertTrue(rootCause instanceof CertificateRevokedException);
                } else
                    fail("Expected CertificateRevokedException, but " + secondCause.getClass().getSimpleName() + " was thrown.");
            } else
                fail("Expected CertificateRevokedException, but " + cause.getClass().getSimpleName() + " was thrown.");
        }
    }
    
    @Test
    public void testTrustedURL() throws IOException
    {
        _read(new URL("https://www.google.com"));
        assertArrayEquals("The URL should have been trusted", null, resultETypes);
    }
    
    @Test
    public void testSubjectAlternativeNames() throws IOException
    {
        if (resultWrongHost == null)
            _read(new URL("https://wrong.host.badssl.com/"));
        
        ResourceBundle bundle = ResourceBundle.getBundle("de.adito.trustmanager.dialogMessage", Locale.getDefault());
        String testString = bundle.getString("firstMsg") + "\n\n" + bundle.getString("wrongHost") + "\n\n";
        
        Assert.assertTrue("No SubjectAlternativeNames found", testString.length() < resultString.length());
    }
    
    @Test
    public void testCreateTrustStore() throws IOException
    {
        if (chain == null)
            _read(new URL("https://wrong.host.badssl.com/"));
        ICustomTrustStore testTrustStore = new JKSCustomTrustStore(path);
        
        testTrustStore.add("testCert", chain[chain.length - 1], true);
        Assert.assertTrue("TestTrustStore was not created", Files.isRegularFile(path));
    }
    
    @Test
    public void testSaveCertificatePermanently() throws IOException
    {
        if (chain == null)
            _read(new URL("https://wrong.host.badssl.com/"));
        ICustomTrustStore testTrustStore = new JKSCustomTrustStore(path);
        
        testTrustStore.add("testCert", chain[chain.length - 1], true);
        Assert.assertEquals("Certificate alias is not matching", chain[chain.length - 1], testTrustStore.get("testCert"));
    }
    
    @Test
    public void testSaveCertificateVolatile() throws IOException
    {
        if (chain == null)
            _read(new URL("https://wrong.host.badssl.com/"));
        ICustomTrustStore testTrustStore = new JKSCustomTrustStore(path);
        
        testTrustStore.add("testCert", chain[chain.length - 1], false);
        Assert.assertFalse("Certificate was added permanently, expected it to be volatile", Files.isRegularFile(path));
    }
    
    @After
    public void deleteTrustStore() throws IOException
    {
        Files.deleteIfExists(path);
    }
    
    private String _read(URL pUrl) throws IOException
    {
        try (InputStream inputStream = pUrl.openConnection().getInputStream())
        {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}
