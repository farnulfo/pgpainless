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
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.RevocationState;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.signature.consumer.SignatureVerifier;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.wot.dijkstra.sq.CertSynopsis;
import org.pgpainless.wot.dijkstra.sq.Certification;
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

        // Parse all certificates
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
                policy,
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
            Policy policy,
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
                for (PGPPublicKey key : cert.getValidSubkeys()) {
                    byKeyId.put(key.getKeyID(), byKeyIdEntry);
                }
            }
            byKeyIdEntry.add(cert);

            certSynopsisMap.put(cert.getFingerprint(),
                    new CertSynopsis(cert.getFingerprint(),
                            cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER),
                            revocationStateFromSignature(cert.getRevocationSelfSignature()),
                            new HashSet<>(cert.getValidUserIds())));
        }

        Map<OpenPgpFingerprint, Map<OpenPgpFingerprint, List<Certification>>> certifications = new HashMap<>();

        for (KeyRingInfo validatedTarget : validatedCertificates) {
            PGPPublicKeyRing validatedKeyRing = KeyRingUtils.publicKeys(validatedTarget.getKeys());
            OpenPgpFingerprint targetFingerprint = OpenPgpFingerprint.of(validatedKeyRing);
            PGPPublicKey validatedPrimaryKey = validatedKeyRing.getPublicKey();
            CertSynopsis target = certSynopsisMap.get(targetFingerprint);

            // Direct-Key Signatures by X on Y
            List<PGPSignature> delegations = SignatureUtils.getDelegations(validatedKeyRing);
            for (PGPSignature delegation : delegations) {
                List<KeyRingInfo> issuerCandidates = byKeyId.get(delegation.getKeyID());
                if (issuerCandidates == null) {
                    continue;
                }

                for (KeyRingInfo candidate : issuerCandidates) {
                    PGPPublicKeyRing issuerKeyRing = KeyRingUtils.publicKeys(candidate.getKeys());
                    OpenPgpFingerprint issuerFingerprint = OpenPgpFingerprint.of(issuerKeyRing);
                    PGPPublicKey issuerSigningKey = issuerKeyRing.getPublicKey(delegation.getKeyID());
                    CertSynopsis issuer = certSynopsisMap.get(issuerFingerprint);

                    try {
                        System.out.println("Sig from " + issuerFingerprint + " on " + targetFingerprint);
                        boolean valid = SignatureVerifier.verifyDirectKeySignature(delegation, issuerSigningKey, validatedPrimaryKey, policy, referenceTime.getTimestamp());

                        if (valid) {
                            Map<OpenPgpFingerprint, List<Certification>> sigsBy = certifications.get(issuerFingerprint);
                            if (sigsBy == null) {
                                sigsBy = new HashMap<>();
                                certifications.put(issuerFingerprint, sigsBy);
                            }

                            List<Certification> targetSigs = sigsBy.get(targetFingerprint);
                            if (targetSigs == null) {
                                targetSigs = new ArrayList<>();
                                sigsBy.put(targetFingerprint, targetSigs);
                            }

                            targetSigs.add(new Certification(issuer, Optional.empty(), target, delegation));
                        }
                    } catch (SignatureValidationException e) {
                        LOGGER.warn("Cannot verify signature by " + issuerFingerprint + " on cert of " + targetFingerprint, e);
                    }
                }
            }

            Iterator<String> userIds = validatedPrimaryKey.getUserIDs();
            while (userIds.hasNext()) {
                String userId = userIds.next();
                List<PGPSignature> userIdSigs = SignatureUtils.get3rdPartyCertificationsFor(userId, validatedKeyRing);
                for (PGPSignature certification : userIdSigs) {
                    List<KeyRingInfo> issuerCandidates = byKeyId.get(certification.getKeyID());
                    if (issuerCandidates == null) {
                        continue;
                    }

                    for (KeyRingInfo candidate : issuerCandidates) {
                        PGPPublicKeyRing issuerKeyRing = KeyRingUtils.publicKeys(candidate.getKeys());
                        OpenPgpFingerprint issuerFingerprint = OpenPgpFingerprint.of(issuerKeyRing);
                        PGPPublicKey issuerSigningKey = issuerKeyRing.getPublicKey(certification.getKeyID());
                        CertSynopsis issuer = certSynopsisMap.get(issuerFingerprint);

                        try {
                            System.out.println("Sig from " + issuerFingerprint + " for " + userId + " on " + targetFingerprint);
                            boolean valid = SignatureVerifier.verifySignatureOverUserId(userId, certification, issuerSigningKey, validatedPrimaryKey, policy, referenceTime.getTimestamp());

                            if (valid) {
                                Map<OpenPgpFingerprint, List<Certification>> sigsBy = certifications.get(issuerFingerprint);
                                if (sigsBy == null) {
                                    sigsBy = new HashMap<>();
                                    certifications.put(issuerFingerprint, sigsBy);
                                }

                                List<Certification> targetSigs = sigsBy.get(targetFingerprint);
                                if (targetSigs == null) {
                                    targetSigs = new ArrayList<>();
                                    sigsBy.put(targetFingerprint, targetSigs);
                                }

                                targetSigs.add(new Certification(issuer, Optional.just(userId), target, certification));
                            }
                        } catch (SignatureValidationException e) {
                            LOGGER.warn("Cannot verify signature for '" + userId + "' by " + issuerFingerprint + " on cert of " + targetFingerprint, e);
                        }
                    }
                }
            }
        }

        // Re-order data structure

        // Issuer -> Target, Signatures by an issuer
        Map<OpenPgpFingerprint, List<CertificationSet>> edges = new HashMap<>();
        // Target -> Issuer, Signatures on the target
        Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges = new HashMap<>();

        // for each issuer
        for (OpenPgpFingerprint issuerFp : certifications.keySet()) {
            Map<OpenPgpFingerprint, List<Certification>> issuedBy = certifications.get(issuerFp);

            List<CertificationSet> edge = new ArrayList<>();
            // for each target
            for (OpenPgpFingerprint targetFp : issuedBy.keySet()) {
                List<Certification> onCert = issuedBy.get(targetFp);
                CertificationSet edgeSigs = CertificationSet.empty(certSynopsisMap.get(issuerFp), certSynopsisMap.get(targetFp));
                for (Certification certification : onCert) {
                    edgeSigs.add(certification);
                }
                edge.add(edgeSigs);

                List<CertificationSet> reverseEdge = reverseEdges.get(targetFp);
                if (reverseEdge == null) {
                    reverseEdge = new ArrayList<>();
                    reverseEdges.put(targetFp, reverseEdge);
                }
                reverseEdge.add(edgeSigs);

            }
            edges.put(issuerFp, edge);
        }

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

    @Override
    public String toString() {
        return network.toString();
    }
}
