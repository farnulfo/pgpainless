package org.pgpainless.wot;

import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.subkey_lookup.SubkeyLookup;

public class WebOfTrustCertificateStore extends PGPCertificateDirectory {

    public WebOfTrustCertificateStore(Backend backend, SubkeyLookup subkeyLookup) {
        super(backend, subkeyLookup);
    }

}