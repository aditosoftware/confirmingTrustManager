package de.adito.trustmanager;

import de.adito.trustmanager.store.*;
import org.junit.*;
import sun.security.validator.ValidatorException;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * @author j.boesl, 14.02.19
 */
public class Test_CertificateRevocation
{

  @BeforeClass
  public static void setup() throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
      InvalidAlgorithmParameterException, KeyManagementException, IOException
  {
    System.setProperty("adito.trustmanager.revocation.enabled", "true");

    Path path = Paths.get(System.getProperty("user.dir") + File.separator + "testTrustStore.jks");
    ICustomTrustStore trustStore = new JKSCustomTrustStore(path);
    CustomTrustManager trustManager = new CustomTrustManager(trustStore, TrustManagerBuilder.createDefaultTrustManagers())
    {
      @Override
      protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pE, String pSimpleInfo)
      {
        return false;
      }
    };
    TrustManagerSslContext.initSslContext(trustManager);
  }

  @Test
  public void testRevoked()
  {
    try {
      _read(new URL("https://revoked.badssl.com/"));
      fail("Expected CertificateRevokedException, but no exception was thrown");
    }
    catch (Exception exc) {
      Throwable cause = exc.getCause();
      if (cause instanceof ValidatorException) {
        Throwable secondCause = cause.getCause();
        if (secondCause instanceof CertPathValidatorException) {
          Throwable rootCause = secondCause.getCause();
          assertTrue(rootCause instanceof CertificateRevokedException);
        }
        else
          fail("Expected CertificateRevokedException, but " + secondCause.getClass().getSimpleName() + " was thrown.");
      }
      else
        fail("Expected CertificateRevokedException, but " + cause.getClass().getSimpleName() + " was thrown.");
    }
  }

  private String _read(URL pUrl) throws IOException
  {
    try (InputStream inputStream = pUrl.openConnection().getInputStream()) {
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      return reader.lines().collect(Collectors.joining("\n"));
    }
  }

}
