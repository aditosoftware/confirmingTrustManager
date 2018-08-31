package de.adito.trustmanager.store;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class SimpleCustomTrustStore implements ICustomTrustStore
{

    private Map<String, X509Certificate> mapping = new HashMap<>();

    @Override
    public X509Certificate get(String pAlias)
    {
        return mapping.get(pAlias);
    }

    @Override
    public void add(String pAlias, X509Certificate pCertificate, boolean pPersist)
    {
        mapping.put(pAlias, pCertificate);
    }

}
