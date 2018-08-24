#ConfirmingTrustManager

A java implementation that can validate a X509Certificate with several TrustManagers. In case of a not trusted certificate
a JDialog will be shown. It gives further information on the cause.
The user can decide to trust this certificate once or permanently, which will add the certificate to the truststore.
If the user chooses to cancel the process, a CertificateException will be thrown.