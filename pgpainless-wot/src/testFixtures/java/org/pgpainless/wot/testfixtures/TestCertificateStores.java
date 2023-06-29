// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.testfixtures;

import java.io.IOException;
import java.io.InputStream;

import org.opentest4j.TestAbortedException;
import org.pgpainless.certificate_store.KeyMaterialReader;
import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.backend.InMemoryCertificateDirectoryBackend;
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookup;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.certificate.KeyMaterialReaderBackend;
import pgp.certificate_store.exception.BadDataException;

public class TestCertificateStores {

    private static final KeyMaterialMerger merger = new KeyMaterialMerger() {
        @Override
        public KeyMaterial merge(KeyMaterial data, KeyMaterial existing) throws IOException {
            return data; // Always use newer material
        }
    };

    public static PGPCertificateDirectory disconnectedGraph()
            throws BadDataException, IOException, InterruptedException {
        PGPCertificateDirectory certD = createInMemoryCertificateDirectory();

        certD.insertTrustRoot(getTestVector("cross_signed/foobankCaCert.asc"), merger);
        certD.insert(getTestVector("cross_signed/foobankEmployeeCert.asc"), merger);
        certD.insert(getTestVector("cross_signed/foobankAdminCert.asc"), merger);
        certD.insert(getTestVector("cross_signed/barbankCaCert.asc"), merger);
        certD.insert(getTestVector("cross_signed/barbankEmployeeCert.asc"), merger);

        return certD;
    }

    public static PGPCertificateDirectory emptyGraph() {
        PGPCertificateDirectory certD = createInMemoryCertificateDirectory();

        return certD;
    }

    public static PGPCertificateDirectory oneDelegationGraph() throws BadDataException, IOException, InterruptedException {
        PGPCertificateDirectory certD = createInMemoryCertificateDirectory();
        certD.insert(getTestVector("cross_signed/foobankAdminCert.asc"), merger);
        certD.insert(getTestVector("cross_signed/barbankCaCert.asc"), merger);

        return certD;
    }

    private static PGPCertificateDirectory createInMemoryCertificateDirectory() {
        SubkeyLookup subkeyLookup = new InMemorySubkeyLookup();
        KeyMaterialReaderBackend readerBackend = new KeyMaterialReader();
        PGPCertificateDirectory.Backend backend = new InMemoryCertificateDirectoryBackend(readerBackend);
        PGPCertificateDirectory certD = new PGPCertificateDirectory(backend, subkeyLookup);
        return certD;
    }

    private static InputStream requireResource(String resourceName) {
        InputStream inputStream = TestCertificateStores.class.getClassLoader().getResourceAsStream(resourceName);
        if (inputStream == null) {
            throw new TestAbortedException("Cannot read resource " + resourceName + ": InputStream is null.");
        }
        return inputStream;
    }

    private static InputStream getTestVector(String testVectorName) {
        return requireResource("test_vectors/" + testVectorName);
    }
}
