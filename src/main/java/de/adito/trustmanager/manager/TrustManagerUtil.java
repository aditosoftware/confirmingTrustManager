package de.adito.trustmanager.manager;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustManagerUtil {
    public static char[] HEX_DIGITS = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    public static void loadKeyStore(KeyStore pKeyStore, String pPassword, Path pPath) throws IOException, CertificateException, NoSuchAlgorithmException {
        if (pPath == null || !Files.isRegularFile(pPath))
            pKeyStore.load(null, pPassword.toCharArray());
        else {
            try (InputStream is = Files.newInputStream(pPath)) {
                pKeyStore.load(is, pPassword.toCharArray());
            }
        }
    }

    public static void saveKeyStore(KeyStore pKeyStore, String pPassword, Path pPath) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        try (OutputStream out = Files.newOutputStream(pPath)) {
            pKeyStore.store(out, pPassword.toCharArray());
        }
    }

    public static String parseDN(String dn, String field) {
        String[] fields = dn.split("\\s*,\\s*");
        for (String f : fields) {
            if (f.toUpperCase().startsWith(field.toUpperCase() + "=")) {
                return f.substring(f.indexOf('=') + 1);
            }
        }
        return null;
    }

    public static String toHexString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(HEX_DIGITS[(b & 0xf0) >> 4]);
            sb.append(HEX_DIGITS[b & 0xf]);
            sb.append(':');
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    public static String hashMD5(X509Certificate pCert) {
        try {
            return hash(MessageDigest.getInstance("MD5"), pCert);
        } catch (NoSuchAlgorithmException pE) {
            throw new RuntimeException(pE);
        }
    }

    public static String hashSHA1(X509Certificate pCert) {
        try {
            return hash(MessageDigest.getInstance("SHA1"), pCert);
        } catch (NoSuchAlgorithmException pE) {
            throw new RuntimeException(pE);
        }
    }

    static String hash(MessageDigest digest, X509Certificate cert) {
        try {
            return toHexString(digest.digest(cert.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
