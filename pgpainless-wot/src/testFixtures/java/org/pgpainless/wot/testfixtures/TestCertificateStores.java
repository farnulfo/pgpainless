// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.testfixtures;

import org.opentest4j.TestAbortedException;
import org.pgpainless.certificate_store.KeyMaterialReader;
import org.pgpainless.wot.WebOfTrustCertificateStore;
import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;

public class TestCertificateStores {

    private static final KeyMaterialMerger merger = new KeyMaterialMerger() {
        @Override
        public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) throws IOException {
            return data; // Always use newer material
        }
    };

    private static InputStream requireResource(String resourceName) {
        InputStream inputStream = TestCertificateStores.class.getClassLoader().getResourceAsStream(resourceName);
        if (inputStream == null) {
            throw new TestAbortedException("Cannot read resource " + resourceName + ": InputStream is null.");
        }
        return inputStream;
    }

    public static WebOfTrustCertificateStore disconnectedGraph()
            throws BadDataException, IOException, InterruptedException {
        SubkeyLookup subkeyLookup = new InMemorySubkeyLookup();
        KeyMaterialReaderBackend readerBackend = new KeyMaterialReader();
        PGPCertificateDirectory.Backend backend = new InMemoryCertificateDirectoryBackend(readerBackend);
        WebOfTrustCertificateStore wotStore = new WebOfTrustCertificateStore(backend, subkeyLookup);

        wotStore.insertTrustRoot(getTestVector("cross_signed/foobankCaCert.asc"), merger);
        wotStore.insert(getTestVector("cross_signed/foobankEmployeeCert.asc"), merger);
        wotStore.insert(getTestVector("cross_signed/foobankAdminCert.asc"), merger);
        wotStore.insert(getTestVector("cross_signed/barbankCaCert.asc"), merger);
        wotStore.insert(getTestVector("cross_signed/barbankEmployeeCert.asc"), merger);

        return wotStore;
    }

    private static InputStream getTestVector(String testVectorName) {
        return requireResource("test_vectors/" + testVectorName);
    }
}
