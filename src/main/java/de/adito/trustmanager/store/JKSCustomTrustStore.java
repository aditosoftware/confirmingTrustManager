package de.adito.trustmanager.store;

import de.adito.trustmanager.TrustManagerUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class JKSCustomTrustStore implements ICustomTrustStore {
    private Path path;
    private KeyStore ks;

    public JKSCustomTrustStore() throws KeyStoreException {
        this(null);
    }

    public JKSCustomTrustStore(Path pPath) throws KeyStoreException {
        if (pPath == null)
            pPath = Paths.get("trustStore.jks");
        path = pPath;
        ks = KeyStore.getInstance("JKS");
        _loadKS();
    }

    private void _loadKS() {
        try {
            TrustManagerUtil.loadKeyStore(ks, "changeit", path);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private void _saveKS() {
        try {
            TrustManagerUtil.saveKeyStore(ks, "changeit", path);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }


    @Override
    public synchronized X509Certificate get(String pAlias) {
        try {
            return (X509Certificate) ks.getCertificate(pAlias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized void add(String pAlias, X509Certificate pCertificate) {
        try {
            ks.setCertificateEntry(pAlias, pCertificate);
            _saveKS();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
