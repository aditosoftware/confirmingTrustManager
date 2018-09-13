package de.adito.trustmanager;

import de.adito.trustmanager.confirmingui.ConfirmingUITrustManager;
import org.junit.BeforeClass;
import org.junit.Test;

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
import java.util.stream.Collectors;

public class Test_showJDialog
{
    
    @BeforeClass
    public static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            InvalidAlgorithmParameterException, KeyManagementException, IOException
    {
        //Locale locale = new Locale("en");
        //Locale.setDefault(locale);
        SSLContext sslContext = ConfirmingUITrustManager.createSslContext();
        SSLContext.setDefault(sslContext);
    }
    
    @Test
    public void test() throws IOException
    {
        _read(new URL("https://expired.badssl.com/"));
        _read(new URL("https://wrong.host.badssl.com/"));
        _read(new URL("https://self-signed.badssl.com"));
        _read(new URL("https://untrusted-root.badssl.com/"));
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
