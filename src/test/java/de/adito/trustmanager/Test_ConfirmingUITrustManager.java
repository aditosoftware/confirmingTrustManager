package de.adito.trustmanager;


import de.adito.trustmanager.confirmingui.ConfirmingUITrustManager;
import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.stream.Collectors;

public class Test_ConfirmingUITrustManager {

    @BeforeAll
    static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException {

       //Locale.setDefault(new Locale("en"));

        SSLContext sslContext = ConfirmingUITrustManager.createSslContext(new JKSCustomTrustStore());
        SSLContext.setDefault(sslContext);
    }

    @Test
    void test() throws IOException {
        //_read(new URL("https://expired.badssl.com/"));
        //_read(new URL("https://wrong.host.badssl.com/"));
        //_read(new URL("https://self-signed.badssl.com"));
        _read(new URL("https://untrusted-root.badssl.com/"));
        _read(new URL("https://gitintern.aditosoftware.local"));
        //_read(new URL("https://revoked.badssl.com/"));

    }

    private String _read(URL pUrl) throws IOException {
        try (InputStream inputStream = pUrl.openConnection().getInputStream()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}
