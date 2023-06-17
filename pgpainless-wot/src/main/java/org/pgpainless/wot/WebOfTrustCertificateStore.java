package org.pgpainless.wot;

import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateDirectory;
import pgp.certificate_store.MergeCallback;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class WebOfTrustCertificateStore implements CertificateDirectory {

    private final CertificateDirectory certificateDirectory;

    public WebOfTrustCertificateStore(CertificateDirectory certificateDirectory) {
        this.certificateDirectory = certificateDirectory;
    }

    public Certificate getTrustRoot() throws BadDataException, IOException {
        try {
            return getCertificate("trust-root");
        } catch (BadNameException e) {
            throw new AssertionError("The underlying certificate directory MUST support getting a trust-root certificate.");
        }
    }

    @Override
    public Certificate getCertificate(String identifier)
            throws IOException, BadNameException, BadDataException {
        return certificateDirectory.getCertificate(identifier);
    }

    @Override
    public Certificate getCertificateIfChanged(String identifier, String tag)
            throws IOException, BadNameException, BadDataException {
        return certificateDirectory.getCertificateIfChanged(identifier, tag);
    }

    @Override
    public Certificate insertCertificate(InputStream data, MergeCallback merge)
            throws IOException, InterruptedException, BadDataException {
        return certificateDirectory.insertCertificate(data, merge);
    }

    @Override
    public Certificate tryInsertCertificate(InputStream data, MergeCallback merge)
            throws IOException, BadDataException {
        return certificateDirectory.tryInsertCertificate(data, merge);
    }

    @Override
    public Certificate insertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, InterruptedException, BadDataException, BadNameException {
        return certificateDirectory.insertCertificateBySpecialName(specialName, data, merge);
    }

    @Override
    public Certificate tryInsertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadDataException, BadNameException {
        return certificateDirectory.tryInsertCertificateBySpecialName(specialName, data, merge);
    }

    @Override
    public Iterator<Certificate> getCertificates() {
        return certificateDirectory.getCertificates();
    }

    @Override
    public Iterator<String> getFingerprints() {
        return certificateDirectory.getFingerprints();
    }
}
