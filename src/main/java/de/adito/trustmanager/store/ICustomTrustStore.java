package de.adito.trustmanager.store;

import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public interface ICustomTrustStore {

    X509Certificate get(String pAlias);

    Path getPath();
    KeyStore getKs();

    void add(String pAlias, X509Certificate pCertificate, boolean pPersistent);
}
