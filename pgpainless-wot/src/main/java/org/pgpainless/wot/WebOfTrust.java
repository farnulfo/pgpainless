// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.RevocationState;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.wot.dijkstra.sq.CertSynopsis;
import org.pgpainless.wot.dijkstra.sq.CertificationSet;
import org.pgpainless.wot.dijkstra.sq.Network;
import org.pgpainless.wot.dijkstra.sq.Optional;
import org.pgpainless.wot.dijkstra.sq.ReferenceTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pgp.certificate_store.certificate.Certificate;
import pgp.certificate_store.exception.BadDataException;

public class WebOfTrust implements CertificateAuthority {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebOfTrust.class);

    private final WebOfTrustCertificateStore certificateStore;
    private Network network;

    public WebOfTrust(WebOfTrustCertificateStore certificateStore) {
        this.certificateStore = certificateStore;
    }

    /**
     * Do the heavy lifting of calculating the web of trust.
     */
    public void initialize() throws BadDataException, IOException {
        Iterator<Certificate> certificates = certificateStore.getAllItems();
        IterableIterator<Certificate> iterable = new IterableIterator<>(certificates);
        network = fromCertificates(iterable, PGPainless.getPolicy(), Optional.just(ReferenceTime.now()));
    }


    /**
     * Create a {@link Network} from a set of certificates.
     *
     * @param certificates set of certificates
     * @param policy evaluation policy
     * @param optReferenceTime reference time for evaluation
     * @return network
     */
    public static Network fromCertificates(
            Iterable<Certificate> certificates,
            Policy policy,
            Optional<ReferenceTime> optReferenceTime) {
        ReferenceTime referenceTime = optReferenceTime.isPresent() ? optReferenceTime.get() : ReferenceTime.now();
        List<KeyRingInfo> validCerts = new ArrayList<>();
        for (Certificate cert : certificates) {
            try {
                PGPPublicKeyRing publicKey = PGPainless.readKeyRing().publicKeyRing(cert.getInputStream());
                // No Certificate data
                if (publicKey == null) {
                    throw new IOException("Certificate " + cert.getFingerprint() + " was null. No certificate data?");
                }

                KeyRingInfo info = new KeyRingInfo(publicKey, policy, referenceTime.getTimestamp());
                if (info.getValidUserIds().isEmpty()) {
                    LOGGER.warn("Certificate " + cert.getFingerprint() + " has no valid user-ids. Ignore.");
                    // Ignore invalid cert
                    // TODO: Allow user-id-less certificates?
                } else {
                    validCerts.add(info);
                }
            } catch (IOException e) {
                LOGGER.warn("Could not parse certificate " + cert.getFingerprint(), e);
            }
        }

        return fromValidCertificates(
                validCerts,
                referenceTime
        );
    }

    /**
     * Create a {@link Network} from a set of validated certificates.
     *
     * @param validatedCertificates set of validated certificates
     * @param referenceTime reference time
     * @return network
     */
    public static Network fromValidCertificates(
            Iterable<KeyRingInfo> validatedCertificates,
            ReferenceTime referenceTime) {

        Map<OpenPgpFingerprint, KeyRingInfo> byFingerprint = new HashMap<>();
        Map<Long, List<KeyRingInfo>> byKeyId = new HashMap<>();

        Map<OpenPgpFingerprint, CertSynopsis> certSynopsisMap = new HashMap<>();

        for (KeyRingInfo cert : validatedCertificates) {
            // noinspection Java8MapApi
            if (byFingerprint.get(cert.getFingerprint()) == null) {
                byFingerprint.put(cert.getFingerprint(), cert);
            }
            List<KeyRingInfo> byKeyIdEntry = byKeyId.get(cert.getKeyId());

            // noinspection Java8MapApi
            if (byKeyIdEntry == null) {
                byKeyIdEntry = new ArrayList<>();
                byKeyId.put(cert.getKeyId(), byKeyIdEntry);
            }
            byKeyIdEntry.add(cert);

            certSynopsisMap.put(cert.getFingerprint(),
                    new CertSynopsis(cert.getFingerprint(),
                            cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER),
                            revocationStateFromSignature(cert.getRevocationSelfSignature()),
                            new HashSet<>(cert.getValidUserIds())));
        }

        Map<OpenPgpFingerprint, List<CertificationSet>> edges = new HashMap<>();
        Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges = new HashMap<>();

        return new Network(certSynopsisMap, edges, reverseEdges, referenceTime);
    }


    private static RevocationState revocationStateFromSignature(PGPSignature revocation) {
        if (revocation == null) {
            return RevocationState.notRevoked();
        }

        RevocationReason revocationReason = SignatureSubpacketsUtil.getRevocationReason(revocation);
        if (revocationReason == null) {
            return RevocationState.hardRevoked();
        }

        return RevocationAttributes.Reason.isHardRevocation(revocationReason.getRevocationReason()) ?
                RevocationState.hardRevoked() : RevocationState.softRevoked(revocation.getCreationTime());
    }

    @Override
    public boolean isAuthorized(PGPPublicKeyRing certificate, String userId) {
        return false;
    }
}
