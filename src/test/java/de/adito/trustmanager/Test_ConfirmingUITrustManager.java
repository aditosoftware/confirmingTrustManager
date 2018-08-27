package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.ConfirmingUITrustManager;
import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.URL;
import java.nio.file.Paths;
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

        //save trusted certificate in java truststore instead of the project
        //String path = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";
        //SSLContext sslContext = ConfirmingUITrustManager.createSslContext(new JKSCustomTrustStore(Paths.get(path)));

        SSLContext sslContext = ConfirmingUITrustManager.createSslContext(new JKSCustomTrustStore());
        SSLContext.setDefault(sslContext);
    }

    @Test
    void test() throws IOException {
        //_read(new URL("https://expired.badssl.com/"));
        //_read(new URL("https://wrong.host.badssl.com/"));
        //_read(new URL("https://self-signed.badssl.com"));
        _read(new URL("https://untrusted-root.badssl.com/"));
        //_read(new URL("https://revoked.badssl.com/"));

    }

    private String _read(URL pUrl) throws IOException {
        try (InputStream inputStream = pUrl.openConnection().getInputStream()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }
}
