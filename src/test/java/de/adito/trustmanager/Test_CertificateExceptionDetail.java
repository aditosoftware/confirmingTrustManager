package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.CertificateExceptionDetail;
import de.adito.trustmanager.store.ICustomTrustStore;
import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class Test_CertificateExceptionDetail {

    private static CertificateExceptionDetail.EType[] resultETypes;
    private static String resultString;
    private static CertificateExceptionDetail.EType[] resultWrongHost;

    private String _read(URL pUrl) throws IOException
    {
        try (InputStream inputStream = pUrl.openConnection().getInputStream())
        {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    @BeforeAll
    public static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException
    {
        resultString = null;
        resultWrongHost = null;
        ICustomTrustStore trustStore = new JKSCustomTrustStore();
        CustomTrustManager trustManager = new CustomTrustManager(trustStore, CustomTrustManager.createStandardTrustManagers())
        {
            @Override
            protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) throws CertificateException {
                CertificateExceptionDetail exceptionDetail = CertificateExceptionDetail.createExceptionDetail(pChain, pE, pSimpleInfo);
                resultETypes = exceptionDetail.getTypes().toArray(new CertificateExceptionDetail.EType[0]);
                if(resultETypes[0] == CertificateExceptionDetail.EType.WRONG_HOST)
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

    @BeforeEach
    public void resetResult()
    {
        resultETypes = null;
    }

    @Test
    public void testExpired() throws IOException
    {
        _read(new URL("https://expired.badssl.com/"));
        assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }

    @Test
    public void testWrongHost() throws IOException
    {
        if(resultWrongHost == null)
            _read(new URL("https://wrong.host.badssl.com/"));
        else
            resultETypes = resultWrongHost;

        if(resultETypes.length == 1)
            assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST}, resultETypes);
        else
            assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST,
                    CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }

    @Test
    public void testSelfSigned() throws IOException
    {
        _read(new URL("https://self-signed.badssl.com"));
        if(resultETypes.length == 1)
            assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED}, resultETypes);
        else
            assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED,
                    CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }

    @Test
    public void testUntrustedRoot() throws IOException
    {
        _read(new URL("https://untrusted-root.badssl.com/"));
        if(resultETypes.length == 1)
            assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT}, resultETypes);
        else
            assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT,
                    CertificateExceptionDetail.EType.EXPIRED}, resultETypes);
    }

    @Test
    public void testRevoked()
    {
        try {
            _read(new URL("https://revoked.badssl.com/"));
            fail("Expected CertificateRevokedException not thrown");
        }catch(Exception exc){}
    }

    @Test
    public void testTrustedURL() throws IOException
    {
        _read(new URL("https://www.google.com"));
        assertArrayEquals(null, resultETypes);
    }

    @Test
    public void testSubjectAlternativeNames() throws IOException
    {
        if(resultWrongHost == null)
            _read(new URL("https://wrong.host.badssl.com/"));

        ResourceBundle bundle = ResourceBundle.getBundle("de.adito.trustmanager.dialogMessage", Locale.getDefault());
        String testString = bundle.getString("firstMsg") + "\n\n" + bundle.getString("wrongHost") + "\n\n";
        assertTrue(testString.length() < resultString.length(), "No SubjectAlternativeNames found");
    }
}
