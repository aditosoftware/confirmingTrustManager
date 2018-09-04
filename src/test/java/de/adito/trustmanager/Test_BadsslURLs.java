package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.CertificateExceptionDetail;

import de.adito.trustmanager.store.ICustomTrustStore;
import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;

public class Test_BadsslURLs {

    private static CertificateExceptionDetail.EType[] result;

    private String _read(URL pUrl) throws IOException
    {
        try (InputStream inputStream = pUrl.openConnection().getInputStream())
        {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    @BeforeAll
    static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException
    {
        LookAndFeel.setLookAndFeel();
        //Locale.setDefault(new Locale("en"));
        //SSLContext sslContext = ConfirmingUITrustManager.createSslContext(); //old initiator

        ICustomTrustStore trustStore = new JKSCustomTrustStore();
        CustomTrustManager trustManager = new CustomTrustManager(trustStore, CustomTrustManager.createStandardTrustManagers())
        {
            @Override
            protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo) throws CertificateException {
                CertificateExceptionDetail exceptionDetail = CertificateExceptionDetail.createExceptionDetail(pChain, pE, pSimpleInfo);
                result = exceptionDetail.getTypes().toArray(new CertificateExceptionDetail.EType[0]);
                return false;
            }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustManager}, new SecureRandom());

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
        if(result.length == 1)
            Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST}, result);
        else
            Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.WRONG_HOST,
                    CertificateExceptionDetail.EType.EXPIRED}, result);
    }

    @Test
    void testSelfSigned() throws IOException
    {
        _read(new URL("https://self-signed.badssl.com"));
        if(result.length == 1)
            Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED}, result);
        else
            Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.SELF_SIGNED,
                    CertificateExceptionDetail.EType.EXPIRED}, result);
    }

    @Test
    void testUntrustedRoot() throws IOException
    {
        _read(new URL("https://untrusted-root.badssl.com/"));
        if(result.length == 1)
            Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT}, result);
        else
            Assertions.assertArrayEquals(new CertificateExceptionDetail.EType[]{CertificateExceptionDetail.EType.UNTRUSTED_ROOT,
                    CertificateExceptionDetail.EType.EXPIRED}, result);
    }

    @Test
    void testRevoked(){
        try {
            _read(new URL("https://revoked.badssl.com/"));
            fail("CertificateRevokedException not thrown");
        }catch(Exception exc){}
    }
}
