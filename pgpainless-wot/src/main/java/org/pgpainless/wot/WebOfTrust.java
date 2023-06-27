// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

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
import org.pgpainless.wot.sugar.IterableIterator;
import org.pgpainless.wot.sugar.Supplier;
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
        List<KeyRingInfo> validCerts = parseValidCertificates(certificates, policy, referenceTime.getTimestamp());

        LOGGER.debug("Successfully parsed " + validCerts.size() + " certificates.");
        return fromValidCertificates(
                validCerts,
                policy,
                referenceTime
        );
    }

    private static List<KeyRingInfo> parseValidCertificates(Iterable<Certificate> certificates, Policy policy, Date referenceTime) {
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
            List<KeyRingInfo> validatedCertificates,
            Policy policy,
            ReferenceTime referenceTime) {

        // TODO: Move heavy lifting from NetworkBuilder constructor to buildNetwork()?
        NetworkBuilder nb = new NetworkBuilder(validatedCertificates, policy, referenceTime);
        return nb.buildNetwork();
    }

    /**
     * Class for building the {@link Network Flow network} from the given set of OpenPGP keys.
     *
     */
    private static final class NetworkBuilder {

        // certificates keyed by fingerprint
        private final Map<OpenPgpFingerprint, KeyRingInfo> byFingerprint = new HashMap<>();
        // certificates keyed by (sub-) key-id
        private final Map<Long, List<KeyRingInfo>> byKeyId = new HashMap<>();
        // certificate synopses keyed by fingerprint
        private final Map<OpenPgpFingerprint, CertSynopsis> certSynopsisMap = new HashMap<>();

        // Issuer -> Targets, edges keyed by issuer
        private final Map<OpenPgpFingerprint, List<CertificationSet>> edges = new HashMap<>();
        // Target -> Issuers, edges keyed by target
        private final Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges = new HashMap<>();

        private final Policy policy;
        private final ReferenceTime referenceTime;

        private NetworkBuilder(List<KeyRingInfo> validatedCertificates,
                               Policy policy,
                               ReferenceTime referenceTime) {
            this.policy = policy;
            this.referenceTime = referenceTime;

            synopsizeCertificates(validatedCertificates);
            findEdges(validatedCertificates);
        }

        private void synopsizeCertificates(List<KeyRingInfo> validatedCertificates) {
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

            Map<String, RevocationState> userIds = new HashMap<>();
            for (String userId : cert.getUserIds()) {
                RevocationState state = revocationStateFromSignature(cert.getUserIdRevocation(userId));
                userIds.put(userId, state);
            }

            // index synopses
            Date expirationDate;
            try {
                expirationDate = cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER);
            } catch (NoSuchElementException e) {
                // Some keys are malformed and have no KeyFlags
                return;
            }
            certSynopsisMap.put(cert.getFingerprint(),
                    new CertSynopsis(cert.getFingerprint(),
                            expirationDate,
                            revocationStateFromSignature(cert.getRevocationSelfSignature()),
                            userIds));

        }

        private void findEdges(List<KeyRingInfo> validatedCertificates) {
            // Identify certifications and delegations
            // Target = cert carrying a signature
            for (KeyRingInfo validatedTarget : validatedCertificates) {
                findEdgesWithTarget(validatedTarget);
            }
        }

        private void findEdgesWithTarget(KeyRingInfo validatedTarget) {
            PGPPublicKeyRing validatedTargetKeyRing = KeyRingUtils.publicKeys(validatedTarget.getKeys());
            OpenPgpFingerprint targetFingerprint = OpenPgpFingerprint.of(validatedTargetKeyRing);
            PGPPublicKey targetPrimaryKey = validatedTargetKeyRing.getPublicKey();
            CertSynopsis target = certSynopsisMap.get(targetFingerprint);

            // Direct-Key Signatures (delegations) by X on Y
            List<PGPSignature> delegations = SignatureUtils.getDelegations(validatedTargetKeyRing);
            for (PGPSignature delegation : delegations) {
                processDelegation(targetPrimaryKey, target, delegation);
            }

            // Certification Signatures by X on Y over user-ID U
            Iterator<String> userIds = targetPrimaryKey.getUserIDs();
            while (userIds.hasNext()) {
                String userId = userIds.next();
                List<PGPSignature> userIdSigs = SignatureUtils.get3rdPartyCertificationsFor(userId, validatedTargetKeyRing);
                processCertification(targetPrimaryKey, target, userId, userIdSigs);
            }
        }

        private void processDelegation(PGPPublicKey targetPrimaryKey,
                                       CertSynopsis target,
                                       PGPSignature delegation) {
            List<KeyRingInfo> issuerCandidates = byKeyId.get(delegation.getKeyID());
            if (issuerCandidates == null) {
                return;
            }

            for (KeyRingInfo candidate : issuerCandidates) {
                PGPPublicKeyRing issuerKeyRing = KeyRingUtils.publicKeys(candidate.getKeys());
                OpenPgpFingerprint issuerFingerprint = OpenPgpFingerprint.of(issuerKeyRing);
                PGPPublicKey issuerSigningKey = issuerKeyRing.getPublicKey(delegation.getKeyID());
                CertSynopsis issuer = certSynopsisMap.get(issuerFingerprint);
                try {
                    boolean valid = SignatureVerifier.verifyDirectKeySignature(delegation, issuerSigningKey,
                            targetPrimaryKey, policy, referenceTime.getTimestamp());
                    if (valid) {
                        indexEdge(CertificationFactory.fromDelegation(issuer, target, delegation));
                    }
                } catch (SignatureValidationException e) {
                    LOGGER.warn("Cannot verify signature by " + issuerFingerprint + " on cert of " + OpenPgpFingerprint.of(targetPrimaryKey), e);
                }
            }
        }

        private void processCertification(PGPPublicKey targetPrimaryKey,
                                          CertSynopsis target,
                                          String userId, List<PGPSignature> userIdSigs) {
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
                        boolean valid = SignatureVerifier.verifySignatureOverUserId(userId, certification,
                                issuerSigningKey, targetPrimaryKey, policy, referenceTime.getTimestamp());
                        if (valid) {
                            indexEdge(CertificationFactory.fromCertification(issuer, userId, target, certification));
                        }
                    } catch (SignatureValidationException e) {
                        LOGGER.warn("Cannot verify signature for '" + userId + "' by " + issuerFingerprint + " on cert of " + target.getFingerprint(), e);
                    }
                }
            }
        }

        private void indexEdge(Certification certification) {
            OpenPgpFingerprint issuer = certification.getIssuer().getFingerprint();
            OpenPgpFingerprint target = certification.getTarget().getFingerprint();

            List<CertificationSet> outEdges = getOrDefault(edges, issuer, ArrayList::new);
            indexOutEdge(outEdges, certification);

            List<CertificationSet> inEdges = getOrDefault(reverseEdges, target, ArrayList::new);
            indexInEdge(inEdges, certification);
        }

        private void indexOutEdge(List<CertificationSet> outEdges, Certification certification) {
            OpenPgpFingerprint target = certification.getTarget().getFingerprint();
            for (CertificationSet outEdge : outEdges) {
                if (target.equals(outEdge.getTarget().getFingerprint())) {
                    outEdge.add(certification);
                    return;
                }
            }
            outEdges.add(CertificationSet.fromCertification(certification));
        }

        private void indexInEdge(List<CertificationSet> inEdges, Certification certification) {
            OpenPgpFingerprint issuer = certification.getIssuer().getFingerprint();
            for (CertificationSet inEdge : inEdges) {
                if (issuer.equals(inEdge.getIssuer().getFingerprint())) {
                    inEdge.add(certification);
                    return;
                }
            }
            inEdges.add(CertificationSet.fromCertification(certification));
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

    Network getNetwork() {
        return network;
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
