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
import java.text.DateFormat;
import java.util.*;

public class CertificateExceptionDetail {

    private ArrayList<EType> typeArray;
    private X509Certificate[] chain;
    private String errorCode;

    private CertificateExceptionDetail(ArrayList<EType> pType, X509Certificate[] pChain, String pErrorCode) {
        this.typeArray = pType;
        this.chain = pChain;
        this.errorCode = pErrorCode;
    }

    public static CertificateExceptionDetail createExceptionDetail(X509Certificate[] pChain, CertificateException pCertificateException, String pSimpleInfo) throws CertificateException {
        //CertificateExceptionDetail trustDetail;
        String errorCode = "";
        ArrayList<EType> typeArray = new ArrayList<>();

        if (_checkIsSelfSigned(pChain[0])) {
            typeArray.add(EType.SELF_SIGNED);
            errorCode = "PKIX_ERROR_SELF_SIGNED_CERT";

            //expired, selfsigned and untrusted all are
            //instance of ValidatorException, if Exception contains 'building' in its string, it is selfsigned, or untrusted root
        } else if(pCertificateException.getMessage().contains("PKIX path building failed") && !_checkIsSelfSigned(pChain[0])) {
            typeArray.add(EType.UNTRUSTED_ROOT);
            errorCode = "SEC_ERROR_UNKNOWN_ISSUER";

        } else if(pSimpleInfo != null && !_checkHostname(pSimpleInfo, pChain)){
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

        return new CertificateExceptionDetail(typeArray, pChain, errorCode);
        //return trustDetail._makeExceptionMessage(pSimpleInfo, errorCode);
    }

    String makeExceptionMessage(String pSimpleInfo) {
        ResourceBundle bundle = ResourceBundle.getBundle("de.adito.trustmanager.dialogMessage", Locale.getDefault());
        if(pSimpleInfo == null)
            pSimpleInfo = bundle.getString("simpleInfoNull");

        String message = bundle.getString("firstMsg") + "\n\n";
        for(EType type : typeArray) {
            switch (type) {
                case EXPIRED:
                    //new Date() returns current time
                    message += String.format(bundle.getString("expired1") + "%1$s " +
                                    bundle.getString("expired2")+ "%2$s.\n" ,
                            _formatDate(chain[0].getNotAfter()), _formatDate(new Date()));
                    break;

                case WRONG_HOST:
                    message += bundle.getString("wrongHost") + "\n" + _getSubjectAlternativeNames() + "\n";
                    break;

                case SELF_SIGNED:
                    message += bundle.getString("selfSigned")+ "\n";
                    break;

                case UNTRUSTED_ROOT:
                    message += bundle.getString("untrustedRoot")+ "\n";
                    break;

                default: //UNKNOWN
                    message += bundle.getString("unknown")+ "\n";
                    break;
            }
        }
        message += "\n" + bundle.getString("errorCode") + "\t" + errorCode + "\n" +
                bundle.getString("server") + "\t" + pSimpleInfo + "\n\n" +
                bundle.getString("endWarningMsg") + "\n";
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

    private static boolean _checkHostname(String pHostname, X509Certificate[] pChain){
        try {
            HostnameChecker.getInstance(HostnameChecker.TYPE_TLS).match(pHostname, pChain[0]);
            return true;
        } catch (CertificateException exc){
            return false;
        }
    }

    private String _formatDate(Date pDate) {
        DateFormat dateFormat = DateFormat.getDateInstance(
                DateFormat.FULL, Locale.getDefault());
        DateFormat timeFormat = DateFormat.getTimeInstance(
                DateFormat.DEFAULT, Locale.getDefault());

        return dateFormat.format(pDate) + ", " + timeFormat.format(pDate);
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
        StringBuilder names = new StringBuilder();
        while (itAltNames.hasNext()) {
            List extensionEntry = (List) itAltNames.next();
            //nameType:  2 is DNS, 7 is IP
            Integer nameType = (Integer) extensionEntry.get(0);
            //if nameType is 2, extensionEntry is DNS and returned as String
            if(nameType == 2) {
                names.append((String) extensionEntry.get(1));
            }

            //if nameType is 7, extensionEntry is IP and returned as byteArray
            if(nameType == 7){
                //handle byteArray with ASN.1 decoder
                //code not yet tested
                try {
                    Oid oid = new Oid((byte[]) extensionEntry.get(1));
                    names.append(oid.toString());
                } catch (GSSException e) {
                    //Do nothing. Go on to next SubAltName
                }
            }

            if(itAltNames.hasNext()){
                names.append(", ");
            }
        }

        return names.toString();
    }

    public ArrayList<EType> getTypeArray(){
        return typeArray;
    }

    public enum EType {
        EXPIRED,
        WRONG_HOST,
        SELF_SIGNED,
        UNTRUSTED_ROOT,
        UNKNOWN
    }
}


