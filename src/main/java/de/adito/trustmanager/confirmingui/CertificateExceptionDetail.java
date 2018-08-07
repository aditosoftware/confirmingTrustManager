package de.adito.trustmanager.confirmingui;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateExceptionDetail {

    private Type type;
    private X509Certificate[] chain;

    private CertificateExceptionDetail(Type type, X509Certificate[] chain) {
        this.type = type;
        this.chain = chain;
    }

    public static String createTrustDetail(CertificateException pCertificateException, String pSimpleInfo, X509Certificate[] chain) throws CertificateException {
        CertificateExceptionDetail trustDetail;
        String errorCode;
        String certMessage = pCertificateException.getMessage();

        // compareTo() return value less than 0 if this Date is before the Date argument
        //what if time on computer is changed?
        if (chain[0].getNotAfter().compareTo(new Date()) < 0) {
            //default timezone would be "CEST"
            //TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            trustDetail = new CertificateExceptionDetail(Type.EXPIRED, chain);
            errorCode = "SEC_ERROR_EXPIRED_CERTIFICATE";

        }else if (checkIsSelfSigned(chain[0])) {
            trustDetail = new CertificateExceptionDetail(Type.SELF_SIGNED, chain);
            errorCode = "PKIX_ERROR_SELF_SIGNED_CERT";

            //self signed and untrusted root have same exception message
        } else if (("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: " +
                "unable to find valid certification path to requested target").equals(certMessage) && !checkIsSelfSigned(chain[0])) {
            trustDetail = new CertificateExceptionDetail(Type.UNTRUSTED_ROOT, chain);
            errorCode = "SEC_ERROR_UNKNOWN_ISSUER";

        } else if ((String.format("No subject alternative DNS name matching %s found.", pSimpleInfo)).equals(certMessage)) {
            trustDetail = new CertificateExceptionDetail(Type.BAD_HOST, chain);
            errorCode = "SSL_ERROR_BAD_CERT_DOMAIN";

        }else {
            trustDetail = new CertificateExceptionDetail(Type.UNKNOWN, chain);
            errorCode = "SSL_ERROR_UNKNOWN_CERT_ERROR";

        }
        return trustDetail.makeErrorMessage(pSimpleInfo, errorCode);
    }

    private String makeErrorMessage(String pServer, String pErrorCode) {

        String message = "Dem Sicherheitszertifikat dieser Verbindung wird von ihrem PC nicht vertraut.\n\n";
        switch (this.type) {
            case EXPIRED:
                //new Date() returns current time
                message += "Das Zertifikat ist am " + this.chain[0].getNotAfter() + " abgelaufen. Die aktuelle Zeit ist \n" + new Date();
                break;

            case BAD_HOST:
                message += "Das Zertifikat gilt nur für folgende Namen:\n";
                try {
                    message += chain[0].getSubjectAlternativeNames();
                } catch (CertificateParsingException e) {
                    e.printStackTrace();
                }
                break;

            case SELF_SIGNED:
                message += "Dem Zertifikat wird nicht vertraut, weil es vom Aussteller selbst signiert wurde.";
                break;

            case UNTRUSTED_ROOT:
                message += "Dem Zertifikat wird nicht vertraut, weil das Aussteller-Zertifikat unbekannt ist.\n" +
                        "Der Server sendet eventuell nicht die richtigen Zwischen-Zertifikate.\n" +
                        "Eventuell muss ein zusätzliches Stammzertifikat importiert werden.";
                break;

            default: //UNKNOWN
                message += "Platzhalter für Unbekannte Exception";
                break;
        }
        message += "\n\nFehlercode:\t" + pErrorCode + "\n" +
                "Server:\t" + pServer + "\n\n" +
                "Sie können eigenverantwortlich dieser Verbindung vertrauen oder den Vorgang abbrechen.\n";
        return message;
    }

    /*Compare for further information:
    http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
    line 99 ff
     */
    private static boolean checkIsSelfSigned(X509Certificate cert)
            throws CertificateException {
        try {
            // Try to verify certificate signature with its own public key
            cert.verify(cert.getPublicKey());
            return true;

        } catch (SignatureException | InvalidKeyException exc) {
            // Invalid signature --> not self-signed
            return false;

        } catch (NoSuchProviderException | NoSuchAlgorithmException exc) {
            //Exceptions not for checking selfsigned. Maybe throw
            exc.printStackTrace();
            return true;
        }
    }

    enum Type {
        EXPIRED,
        BAD_HOST,
        SELF_SIGNED,
        UNTRUSTED_ROOT,
        UNKNOWN
    }
}
