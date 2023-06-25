// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import pgp.cert_d.PGPCertificateDirectory;
import pgp.cert_d.ReadOnlyPGPCertificateDirectory;
import pgp.cert_d.WritingPGPCertificateDirectory;
import pgp.cert_d.subkey_lookup.SubkeyLookup;
import pgp.certificate_store.certificate.KeyMaterial;
import pgp.certificate_store.certificate.KeyMaterialMerger;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.NoSuchElementException;

import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadNameException;

public class WebOfTrustCertificateStore implements ReadOnlyPGPCertificateDirectory, WritingPGPCertificateDirectory {

    private final PGPCertificateDirectory directory;

    public WebOfTrustCertificateStore(PGPCertificateDirectory.Backend backend, SubkeyLookup subkeyLookup) {
        this(new PGPCertificateDirectory(backend, subkeyLookup));
    }

    public WebOfTrustCertificateStore(PGPCertificateDirectory certificateDirectory) {
        this.directory = certificateDirectory;
    }

    public Iterator<Certificate> getAllItems()
            throws BadDataException, IOException {
        Certificate trustRoot;
        try {
            trustRoot = getTrustRootCertificate();
        } catch (NoSuchElementException e) {
            // ignore
            trustRoot = null;
        }

        return new PrefixedIterator<>(trustRoot, items());
    }

    @Override
    public Certificate getTrustRootCertificate() throws IOException, BadDataException {
        return directory.getTrustRootCertificate();
    }

    @Override
    public Certificate getTrustRootCertificateIfChanged(long tag) throws IOException, BadDataException {
        return directory.getTrustRootCertificateIfChanged(tag);
    }

    @Override
    public Certificate getByFingerprint(String fingerprint) throws IOException, BadNameException, BadDataException {
        return directory.getByFingerprint(fingerprint);
    }

    @Override
    public Certificate getByFingerprintIfChanged(String fingerprint, long tag) throws IOException, BadNameException, BadDataException {
        return null;
    }

    @Override
    public Certificate getBySpecialName(String specialName) throws IOException, BadNameException, BadDataException {
        return directory.getBySpecialName(specialName);
    }

    @Override
    public Certificate getBySpecialNameIfChanged(String specialName, long tag) throws IOException, BadNameException, BadDataException {
        return directory.getBySpecialNameIfChanged(specialName, tag);
    }

    @Override
    public Iterator<Certificate> items() {
        return directory.items();
    }

    @Override
    public Iterator<String> fingerprints() {
        return directory.fingerprints();
    }

    @Override
    public KeyMaterial getTrustRoot() throws IOException, BadDataException {
        return directory.getTrustRoot();
    }

    @Override
    public KeyMaterial insertTrustRoot(InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException, InterruptedException {
        return directory.insertTrustRoot(data, merge);
    }

    @Override
    public KeyMaterial tryInsertTrustRoot(InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException {
        return directory.tryInsertTrustRoot(data, merge);
    }

    @Override
    public Certificate insert(InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException, InterruptedException {
        return directory.insert(data, merge);
    }

    @Override
    public Certificate tryInsert(InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException {
        return directory.tryInsert(data, merge);
    }

    @Override
    public Certificate insertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException, BadNameException, InterruptedException {
        return directory.insertWithSpecialName(specialName, data, merge);
    }

    @Override
    public Certificate tryInsertWithSpecialName(String specialName, InputStream data, KeyMaterialMerger merge) throws IOException, BadDataException, BadNameException {
        return directory.tryInsertWithSpecialName(specialName, data, merge);
    }
}
