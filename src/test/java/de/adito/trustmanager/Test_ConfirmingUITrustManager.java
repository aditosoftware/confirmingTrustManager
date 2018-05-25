package de.adito.trustmanager;

import de.adito.trustmanager.store.JKSCustomTrustStore;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.stream.Collectors;

public class Test_ConfirmingUITrustManager {

    @Test
    public void test() throws IOException, NoSuchAlgorithmException, KeyManagementException, CertificateException, KeyStoreException, InvalidAlgorithmParameterException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        CustomTrustManager trustManager = new ConfirmingUITrustManager(new JKSCustomTrustStore());
        sslContext.init(null, new CustomTrustManager[]{trustManager}, new SecureRandom());
        SSLContext.setDefault(sslContext);

        //_read(new URL("https://expired.badssl.com/"));
        //_read(new URL("https://wrong.host.badssl.com/"));
        _read(new URL("https://self-signed.badssl.com"));
        //_read(new URL("https://untrusted-root.badssl.com/"));
        //_read(new URL("https://revoked.badssl.com/"));
        //_read(new URL("https://pinning-test.badssl.com/"));
    }

    private boolean _test(URL pUrl) {
        try {
            _read(pUrl);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private String _read(URL pUrl) throws IOException {
        try (InputStream inputStream = pUrl.openConnection().getInputStream()) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

}