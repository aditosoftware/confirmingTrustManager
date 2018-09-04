package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.ConfirmingUITrustManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;



public class Test_ConfirmingUITrustManager {

    @BeforeAll
    static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException {

        SSLContext sslContext = ConfirmingUITrustManager.createSslContext();
        SSLContext.setDefault(sslContext);
    }

    @Test
    void testExpired() throws IOException
    {
        _read(new URL("https://expired.badssl.com/"));
        Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.EXPIRED}, result);
    }

    @Test
    void testWrongHost() throws IOException
    {
        _read(new URL("https://wrong.host.badssl.com/"));
        Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST}, result);
    }

    @Test
    void testSelfSigned() throws IOException
    {
        _read(new URL("https://self-signed.badssl.com"));
        Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED}, result);
    }

    @Test
    void testUntrustedRoot() throws IOException
    {
        _read(new URL("https://untrusted-root.badssl.com/"));
        Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT}, result);
    }

    @Test
    void testRevoked() {
        try {
            _read(new URL("https://revoked.badssl.com/"));
            fail("CertificateRevokedException not thrown");
        }catch(Exception exc){}
    }
}
