package org.pgpainless.wot;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;

public class WebOfTrust implements CertificateAuthority {

    private final WebOfTrustCertificateStore certificateStore;

    public WebOfTrust(WebOfTrustCertificateStore certificateStore) {
        this.certificateStore = certificateStore;
    }

    /**
     * Do the heavy lifting of calculating the web of trust.
     */
    public void initialize() throws BadDataException, IOException {
        Certificate trustRoot = certificateStore.getTrustRoot();
        
    }

    @Override
    public boolean isAuthorized(PGPPublicKeyRing certificate, String userId) {
        return false;
    }
}
