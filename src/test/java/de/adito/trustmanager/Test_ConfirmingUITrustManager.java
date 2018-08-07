package de.adito.trustmanager;

import de.adito.aditoweb.core.checkpoint.exception.mechanics.AditoException;
import de.adito.aditoweb.swingcommon.lf.LookAndFeelSetter;
import de.adito.trustmanager.confirmingui.ConfirmingUITrustManager;
import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.jupiter.api.*;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.stream.Collectors;

public class Test_ConfirmingUITrustManager {

    @BeforeAll
    static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException {
        try {
//    LookAndFeel lf = new AditoSyntheticaLFFlat();
//    UIManager.setLookAndFeel(lf);
            LookAndFeelSetter.set();
        } catch (AditoException e) {
            e.printStackTrace();
        }

        SSLContext sslContext = ConfirmingUITrustManager.createSslContext(new JKSCustomTrustStore());
        SSLContext.setDefault(sslContext);
    }

    @Test
    void test() throws IOException {
        //_read(new URL("https://expired.badssl.com/"));
        _read(new URL("https://wrong.host.badssl.com/"));
        //_read(new URL("https://self-signed.badssl.com"));
        //_read(new URL("https://untrusted-root.badssl.com/"));
        //_read(new URL("https://revoked.badssl.com/"));  // does finish without opening a window
        //_read(new URL("https://pinning-test.badssl.com/")); // does finish without opening a window
    }
    //PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target

    private String _read(URL pUrl) throws IOException {
        try (InputStream inputStream = pUrl.openConnection().getInputStream()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}
