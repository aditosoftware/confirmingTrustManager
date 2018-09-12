# ConfirmingTrustManager

[![Build Status](https://travis-ci.org/aditosoftware/confirmingTrustManager.svg?branch=master)](https://travis-ci.org/aditosoftware/confirmingTrustManager)

A java implementation that can validate a X509Certificate with several TrustManagers (eg ones using the keystore of
Windows or Java). The Java KeyStore will be used as default, unless there is a keystore set in the systemProperties via
`-Djavax.net.ssl.keystore=your/keystore/path`.

In case of a not trusted certificate a JDialog will be shown. It gives further information on the cause, together with an
error code in the favored language of the OS.

A revoked certificate will always end in a RevocationException. Otherwise the dialog can differentiate between following
exceptions:
expired, wrongHost, selfSigned, untrustedRoot, unknown

The user can decide to trust this certificate once or permanently, which will add the certificate to a truststore.
This trustStore has to be given to the CustomTrustManager constructor. Otherwise a nullPointerException will be thrown.

If the user chooses to cancel the process, a CertificateException will be thrown.

An operatingSystem specific trustStore can be added in the CustomTrustManager class.(Atm the implementation is only able
to detect windows operating systems)