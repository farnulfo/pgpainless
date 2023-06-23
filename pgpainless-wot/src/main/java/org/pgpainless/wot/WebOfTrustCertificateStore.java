// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.util.Iterator;
import pgp.certificate_store.certificate.Certificate;

public class WebOfTrustCertificateStore extends PGPCertificateDirectory {

    public WebOfTrustCertificateStore(Backend backend, SubkeyLookup subkeyLookup) {
        super(backend, subkeyLookup);
    }

    public Iterator<Certificate> getAllItems()
            throws BadDataException, IOException {
        Iterator<Certificate> trustRootAndCerts = new PrefixedIterator<>(getTrustRootCertificate(), items());
        return trustRootAndCerts;
    }
}
