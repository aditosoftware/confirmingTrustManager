package de.adito.trustmanager.confirmingui;

import de.adito.trustmanager.*;
import de.adito.trustmanager.store.ICustomTrustStore;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class creates a SSLContext and implements checkCertificateAndShouldPersist used in {@link CustomTrustManager}
 */
public class ConfirmingUITrustManager extends CustomTrustManager
{

    public ConfirmingUITrustManager(ICustomTrustStore pTrustStore, Iterable<X509ExtendedTrustManager> pTrustManagers)
    {
        super(pTrustStore, pTrustManagers);
    }

    /**
     * This method handles the JDialog and its return value. It will throw a CertificateException if r != 0 || r != 1.
     * Otherwise the program returns to {@link CustomTrustManager}.
     */
    protected boolean checkCertificateAndShouldPersist(X509Certificate[] pChain, CertificateException pCertExc, String pSimpleInfo)
            throws CertificateException
    {
        CertificateExceptionDetail certExcDetail = CertificateExceptionDetail.createExceptionDetail(pChain, pCertExc, pSimpleInfo);
        String detailMessage = certExcDetail.makeExceptionMessage(pSimpleInfo);

        AtomicInteger result = new AtomicInteger(-1);
        if (SwingUtilities.isEventDispatchThread())
            result.set(_createDialog(detailMessage));
        else {
            try {
                SwingUtilities.invokeAndWait(() -> result.set(_createDialog(detailMessage)));
            }
            catch (InterruptedException | InvocationTargetException pE) {
                pE.printStackTrace();
            }
        }
        switch (result.get())
        {    // Will decide to trust or not trust the certificate
            case 0:       //trust once
                return false;
            case 1:       //add certificate permanently
                return true;
            default:
                throw pCertExc;  //cancel
        }
    }

    private int _createDialog(String pDetailMessage)
    {
        CertificateExceptionDialog certExceptionDialog = new CertificateExceptionDialog(pDetailMessage);
        certExceptionDialog.setVisible(true);
        
        return certExceptionDialog.getButtonChoice();
    }
}
