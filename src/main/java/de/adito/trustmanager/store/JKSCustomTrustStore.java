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
    private ICustomTrustStore simpleTrustStore;

    public JKSCustomTrustStore() {
        this(null);
    }

    public JKSCustomTrustStore(Path pPath) {
        if (pPath == null)
            pPath = Paths.get("trustStore.jks");
        path = pPath;
        ks = _loadKS();
        simpleTrustStore = new SimpleCustomTrustStore();
    }

    private KeyStore _loadKS() {
        try {
            return TrustManagerUtil.loadKeyStore("changeit", path);
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
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
            X509Certificate certificate = simpleTrustStore.get(pAlias);
            if (certificate != null)
                return certificate;
            return (X509Certificate) ks.getCertificate(pAlias);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public synchronized void add(String pAlias, X509Certificate pCertificate, boolean pPersist) {
        try {
            if (pPersist) {
                ks.setCertificateEntry(pAlias, pCertificate);
                _saveKS();
            } else
                simpleTrustStore.add(pAlias, pCertificate, pPersist);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

}
