# ConfirmingTrustManager

A java implementation that can validate a X509Certificate with several TrustManagers (eg ones using the keystore of
Windows or Java). The Java TrustManager will be used as default.
In case of a not trusted certificate a JDialog will be shown. It gives further information on the cause together with an
error code in the favored language of the OS.

A revoked certificate will always end in a RevocationException. Otherwise the dialog can differentiate between following
exceptions:
expired, wrongHost, selfSigned, untrustedRoot, unknown

The user can decide to trust this certificate once or permanently, which will add the certificate to the given truststore.
If the user chooses to cancel the process, a CertificateException will be thrown.

If a SystemProperty for the truststore is set via `-Djavax.net.ssl.truststore=your/truststore/path`, it will be used as
the truststore, which safes the permanently trusted certificates

An operatingSystem specific trustStore can be added in the CustomTrustManager class