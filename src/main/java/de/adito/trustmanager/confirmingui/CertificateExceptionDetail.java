package de.adito.trustmanager.confirmingui;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import sun.security.util.HostnameChecker;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

public class CertificateExceptionDetail {

    private ArrayList<EType> typeArray;
    private X509Certificate[] chain;

    private CertificateExceptionDetail(ArrayList<EType> pType, X509Certificate[] pChain) {
        this.typeArray = pType;
        this.chain = pChain;
    }

    public static String createExceptionDetail(X509Certificate[] pChain, CertificateException pCertificateException, String pSimpleInfo) throws CertificateException {
        CertificateExceptionDetail trustDetail;
        String errorCode = "";
        ArrayList<EType> typeArray = new ArrayList<>();


        if (_checkIsSelfSigned(pChain[0])) {
            typeArray.add(EType.SELF_SIGNED);
            errorCode = "PKIX_ERROR_SELF_SIGNED_CERT";

            //expired, selfsigned and untrusted all are
            //instance of ValidatorException, if Exception contains 'builing' in its string, it is selfsigned, or untrusted root
        } else if(pCertificateException.getMessage().contains("PKIX path building failed") && !_checkIsSelfSigned(pChain[0])) {
            typeArray.add(EType.UNTRUSTED_ROOT);
            errorCode = "SEC_ERROR_UNKNOWN_ISSUER";

        } else if(!_checkHostname(pSimpleInfo, pChain)){
            typeArray.add(EType.WRONG_HOST);
            errorCode = "SSL_ERROR_BAD_CERT_DOMAIN";

        } else if(pChain[0].getNotAfter().compareTo(new Date()) > 0){
                typeArray.add(EType.UNKNOWN);
                errorCode = "UNKNOWN_CERT_ERROR";

        }

        if(pChain[0].getNotAfter().compareTo(new Date()) < 0) {
            // compareTo() return value less than 0 if Date is before argument
            if(typeArray.isEmpty()){
                errorCode = "SEC_ERROR_EXPIRED_CERTIFICATE";
            }
            typeArray.add(EType.EXPIRED);
        }

        trustDetail = new CertificateExceptionDetail(typeArray, pChain);
        return trustDetail._makeExceptionMessage(pSimpleInfo, errorCode);
    }

    private String _makeExceptionMessage(String pSimpleInfo, String pErrorCode) {

        String message = "Dem Sicherheitszertifikat dieser Verbindung wird von ihrem PC nicht vertraut.\n\n";

        for(EType type : typeArray) {
            switch (type) {
                case EXPIRED:
                    //new Date() returns current time
                    message += "Das Zertifikat ist am " + _formatDate(chain[0].getNotAfter()) + " abgelaufen. Die aktuelle Zeit ist \n" + _formatDate(new Date()) + ".\n";
                    break;

                case WRONG_HOST:
                    message += "Das Zertifikat gilt nur für folgende Namen:\n" + _getSubjectAlternativeNames() + "\n";
                    break;

                case SELF_SIGNED:
                    message += "Dem Zertifikat wird nicht vertraut, weil es vom Aussteller selbst signiert wurde.\n";
                    break;

                case UNTRUSTED_ROOT:
                    message += "Dem Zertifikat wird nicht vertraut, weil das Aussteller-Zertifikat unbekannt ist.\n" +
                            "Der Server sendet eventuell nicht die richtigen Zwischen-Zertifikate.\n" +
                            "Eventuell muss ein zusätzliches Stammzertifikat importiert werden.\n";
                    break;

                default: //UNKNOWN
                    message += "Dem Zertifikat wird aus unbekannten Gründen nicht vertraut.\n";
                    break;
            }
        }
        message += "\nFehlercode:\t" + pErrorCode + "\n" +
                "Server:\t" + pSimpleInfo + "\n\n" +
                "Sie können eigenverantwortlich dieser Verbindung vertrauen oder den Vorgang abbrechen.\n";
        return message;
    }

    /*Compare to:
    http://www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/
    line 99 ff
     */
    private static boolean _checkIsSelfSigned(X509Certificate pCert)
            throws CertificateException {
        try {
            // Try to verify certificate signature with its own public key -> is self-signed
            pCert.verify(pCert.getPublicKey());
            return true;

        } catch (SignatureException | InvalidKeyException exc) {
            // Invalid signature or key -> not self-signed
            return false;

        } catch (NoSuchProviderException | NoSuchAlgorithmException exc) {
            //not able to tell if cert is sef-signed; exception might be displayed as unknown
            return true;
        }
    }

    private String _formatDate(Date pDate) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("EEEE, dd. MMM yyyy, hh:mm:ss");
        return dateFormat.format(pDate);
    }

    /*compare to:
    http://www.javadocexamples.com/java_source/net/sf/jguard/ext/authentication/loginmodules/CertificateLoginModule.java.html
    line 118 ff
    */
    private String _getSubjectAlternativeNames() {
        Collection altNames;
        try {
            altNames = chain[0].getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return "";
        }

        if(altNames == null){
            return "";
        }

        Iterator itAltNames = altNames.iterator();
        String names = "";
        while (itAltNames.hasNext()) {
            List extensionEntry = (List) itAltNames.next();
            //nameType:  2 is DNS, 7 is IP
            Integer nameType = (Integer) extensionEntry.get(0);
            //if nameType is 2, extensionEntry is DNS and returned as String
            if(nameType == 2) {
                names += (String) extensionEntry.get(1);
            }

            //if nameType is 7, extensionEntry is IP and returned as byteArray
            if(nameType == 7){
                //handle byteArray with ASN.1 decoder
                //code not yet tested
                try {
                    Oid oid = new Oid((byte[]) extensionEntry.get(1));
                    names += oid.toString();
                } catch (GSSException e) {
                    //Do nothing. Go on to next SubAltName
                }
            }

            if(itAltNames.hasNext()){
                names += ", ";
            }
        }

        return names;
    }

    private static boolean _checkHostname(String pHostname, X509Certificate[] pChain){
        try {
            HostnameChecker.getInstance(HostnameChecker.TYPE_TLS).match(pHostname, pChain[0]);
            return true;
        } catch (CertificateException exc){
            return false;
        }
    }

    enum EType {
        EXPIRED,
        WRONG_HOST,
        SELF_SIGNED,
        UNTRUSTED_ROOT,
        UNKNOWN
    }
}
