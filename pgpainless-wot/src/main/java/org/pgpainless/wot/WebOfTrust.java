// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

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

/**
 * Build a Web of Trust from a set of certificates.
 * <p>
 * The process of building a WoT is as follows:
 * <ul>
 *     <li>Consume and synopsize all certificates as network nodes</li>
 *     <li>Iterate over cross-certificate signatures and perform signature verification</li>
 *     <li>Identify signatures as edges between nodes</li>
 * </ul>
 *
 * @see <a href="https://sequoia-pgp.gitlab.io/sequoia-wot/">OpenPGP Web of Trust</a>
 */
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
        Iterable<KeyRingInfo> validCerts = parseValidCertificates(certificates, policy, referenceTime.getTimestamp());

        return fromValidCertificates(
                validCerts,
                policy,
                referenceTime
        );
    }

    private static Iterable<KeyRingInfo> parseValidCertificates(Iterable<Certificate> certificates, Policy policy, Date referenceTime) {
        // Parse all certificates
        List<KeyRingInfo> validCerts = new ArrayList<>();
        for (Certificate cert : certificates) {
            try {
                PGPPublicKeyRing publicKey = PGPainless.readKeyRing().publicKeyRing(cert.getInputStream());
                // No Certificate data
                if (publicKey == null) {
                    throw new IOException("Certificate " + cert.getFingerprint() + " was null. No certificate data?");
                }

                KeyRingInfo info = new KeyRingInfo(publicKey, policy, referenceTime);
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
        return validCerts;
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

        // TODO: Move heavy lifting from NetworkBuilder constructor to buildNetwork()?
        NetworkBuilder nb = new NetworkBuilder(validatedCertificates, policy, referenceTime);
        return nb.buildNetwork();
    }

    private static class NetworkBuilder {

        // Index structures
        private final Map<OpenPgpFingerprint, KeyRingInfo> byFingerprint = new HashMap<>();
        private final Map<Long, List<KeyRingInfo>> byKeyId = new HashMap<>();
        private final Map<OpenPgpFingerprint, CertSynopsis> certSynopsisMap = new HashMap<>();

        // Issuer -> Target, Signatures by an issuer
        private final Map<OpenPgpFingerprint, List<CertificationSet>> edges = new HashMap<>();
        // Target -> Issuer, Signatures on the target
        private final Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges = new HashMap<>();

        // TODO: Get rid of this
        Map<OpenPgpFingerprint, Map<OpenPgpFingerprint, List<Certification>>> certifications = new HashMap<>();

        private final Iterable<KeyRingInfo> validatedCertificates;
        private final Policy policy;
        private final ReferenceTime referenceTime;

        private NetworkBuilder(Iterable<KeyRingInfo> validatedCertificates,
                               Policy policy,
                               ReferenceTime referenceTime) {
            this.validatedCertificates = validatedCertificates;
            this.policy = policy;
            this.referenceTime = referenceTime;

            synopsizeCertificates();
            processSignaturesOnCertificates();
            identifyEdges();
        }

        private void synopsizeCertificates() {
            for (KeyRingInfo cert : validatedCertificates) {
                synopsize(cert);
            }
        }

        private void synopsize(KeyRingInfo cert) {

            // index by fingerprint
            if (!byFingerprint.containsKey(cert.getFingerprint())) {
                byFingerprint.put(cert.getFingerprint(), cert);
            }

            // index by key-ID
            List<KeyRingInfo> certsWithKey = byKeyId.get(cert.getKeyId());
            // noinspection Java8MapApi
            if (certsWithKey == null) {
                certsWithKey = new ArrayList<>();
                // TODO: Something is fishy here...
                for (PGPPublicKey key : cert.getValidSubkeys()) {
                    byKeyId.put(key.getKeyID(), certsWithKey);
                }
            }
            certsWithKey.add(cert);

            // index synopses
            certSynopsisMap.put(cert.getFingerprint(),
                    new CertSynopsis(cert.getFingerprint(),
                            cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER),
                            revocationStateFromSignature(cert.getRevocationSelfSignature()),
                            new HashSet<>(cert.getValidUserIds())));
        }

        private void processSignaturesOnCertificates() {
            // Identify certifications and delegations
            // Target = cert carrying a signature
            for (KeyRingInfo validatedTarget : validatedCertificates) {
                processSigsOnCert(validatedTarget);
            }
        }

        private void processSigsOnCert(KeyRingInfo validatedTarget) {
            PGPPublicKeyRing validatedTargetKeyRing = KeyRingUtils.publicKeys(validatedTarget.getKeys());
            OpenPgpFingerprint targetFingerprint = OpenPgpFingerprint.of(validatedTargetKeyRing);
            PGPPublicKey targetPrimaryKey = validatedTargetKeyRing.getPublicKey();
            CertSynopsis target = certSynopsisMap.get(targetFingerprint);

            // Direct-Key Signatures (delegations) by X on Y
            List<PGPSignature> delegations = SignatureUtils.getDelegations(validatedTargetKeyRing);
            for (PGPSignature delegation : delegations) {
                indexAndVerifyDelegation(targetPrimaryKey, target, delegation);
            }

            // Certification Signatures by X on Y over user-ID U
            Iterator<String> userIds = targetPrimaryKey.getUserIDs();
            while (userIds.hasNext()) {
                String userId = userIds.next();
                List<PGPSignature> userIdSigs = SignatureUtils.get3rdPartyCertificationsFor(userId, validatedTargetKeyRing);
                indexAndVerifyCertifications(targetPrimaryKey, target, userId, userIdSigs);
            }
        }

        private void indexAndVerifyDelegation(PGPPublicKey targetPrimaryKey, CertSynopsis target, PGPSignature delegation) {
            List<KeyRingInfo> issuerCandidates = byKeyId.get(delegation.getKeyID());
            if (issuerCandidates == null) {
                return;
            }

            for (KeyRingInfo candidate : issuerCandidates) {

                PGPPublicKeyRing issuerKeyRing = KeyRingUtils.publicKeys(candidate.getKeys());
                OpenPgpFingerprint issuerFingerprint = OpenPgpFingerprint.of(issuerKeyRing);
                PGPPublicKey issuerSigningKey = issuerKeyRing.getPublicKey(delegation.getKeyID());
                CertSynopsis issuer = certSynopsisMap.get(issuerFingerprint);
                boolean valid = false;
                try {
                    valid = SignatureVerifier.verifyDirectKeySignature(delegation, issuerSigningKey, targetPrimaryKey, policy, referenceTime.getTimestamp());
                } catch (SignatureValidationException e) {
                    LOGGER.warn("Cannot verify signature by " + issuerFingerprint + " on cert of " + OpenPgpFingerprint.of(targetPrimaryKey), e);
                }

                if (valid) {
                    Map<OpenPgpFingerprint, List<Certification>> sigsBy = getOrDefault(certifications, issuerFingerprint, HashMap::new);
                    List<Certification> targetSigs = getOrDefault(sigsBy, target.getFingerprint(), ArrayList::new);
                    targetSigs.add(new Certification(issuer, Optional.empty(), target, delegation));
                }
            }
        }

        private void indexAndVerifyCertifications(PGPPublicKey targetPrimaryKey, CertSynopsis target, String userId, List<PGPSignature> userIdSigs) {
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
                        boolean valid = SignatureVerifier.verifySignatureOverUserId(userId, certification, issuerSigningKey, targetPrimaryKey, policy, referenceTime.getTimestamp());

                        if (valid) {
                            Map<OpenPgpFingerprint, List<Certification>> sigsBy = getOrDefault(certifications, issuerFingerprint, HashMap::new);
                            List<Certification> targetSigs = getOrDefault(sigsBy, target.getFingerprint(), ArrayList::new);
                            targetSigs.add(new Certification(issuer, Optional.just(userId), target, certification));
                        }
                    } catch (SignatureValidationException e) {
                        LOGGER.warn("Cannot verify signature for '" + userId + "' by " + issuerFingerprint + " on cert of " + target.getFingerprint(), e);
                    }
                }
            }
        }

        private void identifyEdges() {
            // Re-order data structure
            for (OpenPgpFingerprint issuerFp : certifications.keySet()) {
                Map<OpenPgpFingerprint, List<Certification>> issuedBy = certifications.get(issuerFp);

                // one issuer can issue many edges
                List<CertificationSet> outEdges = new ArrayList<>();
                for (OpenPgpFingerprint targetFp : issuedBy.keySet()) {

                    List<Certification> onCert = issuedBy.get(targetFp);
                    CertificationSet edgeSigs = CertificationSet.empty(certSynopsisMap.get(issuerFp), certSynopsisMap.get(targetFp));
                    for (Certification certification : onCert) {
                        edgeSigs.add(certification);
                    }
                    outEdges.add(edgeSigs);

                    List<CertificationSet> reverseEdge = getOrDefault(reverseEdges, targetFp, ArrayList::new);
                    reverseEdge.add(edgeSigs);

                }
                edges.put(issuerFp, outEdges);
            }
        }

        /**
         * Return the constructed, initialized {@link Network}.
         *
         * @return finished network
         */
        public Network buildNetwork() {
            return new Network(certSynopsisMap, edges, reverseEdges, referenceTime);
        }
    }

    // Map signature to its revocation state
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

    // Java 8 is not supported on old Android
    private static <K, V> V getOrDefault(Map<K, V> map, K key, Supplier<V> defaultValue) {
        V value = map.get(key);
        if (value == null) {
            value = defaultValue.get();
            map.put(key, value);
        }
        return value;
    }

    @Override
    public boolean isAuthorized(PGPPublicKeyRing certificate, String userId) {
        // TODO: Heiko! Implement!
        return false;
    }

    @Override
    public String toString() {
        return network.toString();
    }
}
