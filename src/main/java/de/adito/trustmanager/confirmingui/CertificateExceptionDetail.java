package de.adito.trustmanager.confirmingui;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CertificateExceptionDetail {

    private EType type;
    private X509Certificate[] chain;

    private CertificateExceptionDetail(EType pType, X509Certificate[] pChain) {
        this.type = pType;
        this.chain = pChain;
    }

    public static String createExceptionDetail(X509Certificate[] pChain, CertificateException pCertificateException, String pSimpleInfo) throws CertificateException {
        CertificateExceptionDetail trustDetail;
        String errorCode;
        String certMessage = pCertificateException.getMessage();

        // compareTo() return value less than 0 if this Date is before the Date argument
        //what if time on computer is changed?
        if (pChain[0].getNotAfter().compareTo(new Date()) < 0) {
            //default timezone would be "CEST"
            //TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
            trustDetail = new CertificateExceptionDetail(EType.EXPIRED, pChain);
            errorCode = "SEC_ERROR_EXPIRED_CERTIFICATE";

        }else if (_checkIsSelfSigned(pChain[0])) {
            trustDetail = new CertificateExceptionDetail(EType.SELF_SIGNED, pChain);
            errorCode = "PKIX_ERROR_SELF_SIGNED_CERT";

            //self signed and untrusted root have same exception message
        }else if (("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: " +
                "unable to find valid certification path to requested target").equals(certMessage) && !_checkIsSelfSigned(pChain[0])) {
            trustDetail = new CertificateExceptionDetail(EType.UNTRUSTED_ROOT, pChain);
            errorCode = "SEC_ERROR_UNKNOWN_ISSUER";

        }else if ((String.format("No subject alternative DNS name matching %s found.", pSimpleInfo)).equals(certMessage)) {
            trustDetail = new CertificateExceptionDetail(EType.BAD_HOST, pChain);
            errorCode = "SSL_ERROR_BAD_CERT_DOMAIN";

        }else {
            trustDetail = new CertificateExceptionDetail(EType.UNKNOWN, pChain);
            errorCode = "UNKNOWN_CERT_ERROR";

        }
        return trustDetail._makeExceptionMessage(pSimpleInfo, errorCode);
    }

    private String _makeExceptionMessage(String pSimpleInfo, String pErrorCode) {

        String message = "Dem Sicherheitszertifikat dieser Verbindung wird von ihrem PC nicht vertraut.\n\n";
        switch (this.type) {
            case EXPIRED:
                //new Date() returns current time
                message += "Das Zertifikat ist am " + _formatDate(chain[0].getNotAfter()) + " abgelaufen. Die aktuelle Zeit ist \n" + _formatDate(new Date());
                break;

            case BAD_HOST:
                message += "Das Zertifikat gilt nur für folgende Namen:\n";
                try {
                    message += this.chain[0].getSubjectAlternativeNames();
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
                message += "Dem Zertifikat wird aus noch unbekannten Gründen nicht vertraut.";
                break;
        }
        message += "\n\nFehlercode:\t" + pErrorCode + "\n" +
                "Server:\t" + pSimpleInfo + "\n\n" +
                "Sie können eigenverantwortlich dieser Verbindung vertrauen oder den Vorgang abbrechen.\n";
        return message;
    }

    /*Compare for further information:
    http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
    line 99 ff
     */
    private static boolean _checkIsSelfSigned(X509Certificate pCert)
            throws CertificateException {
        try {
            // Try to verify certificate signature with its own public key
            pCert.verify(pCert.getPublicKey());
            return true;

        } catch (SignatureException | InvalidKeyException exc) {
            // Invalid signature or key --> not self-signed
            return false;

        } catch (NoSuchProviderException | NoSuchAlgorithmException exc) {
            exc.printStackTrace();
            return true;
        }
    }

    private String _formatDate(Date pDate){
        SimpleDateFormat dateFormat = new SimpleDateFormat("EEEE, dd. MMM yyyy, hh:mm:ss");
        return dateFormat.format(pDate);
    }



    enum EType {
        EXPIRED,
        BAD_HOST,
        SELF_SIGNED,
        UNTRUSTED_ROOT,
        UNKNOWN
    }
}
