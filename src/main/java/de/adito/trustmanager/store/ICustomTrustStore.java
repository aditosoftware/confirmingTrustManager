package de.adito.trustmanager.store;

import java.security.cert.X509Certificate;

public interface ICustomTrustStore {

    X509Certificate get(String pAlias);

    void add(String pAlias, X509Certificate pCertificate);
}
