package org.pgpainless.wot.dijkstra.sq;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.RevocationState;
import org.pgpainless.algorithm.RevocationStateType;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;

public class Network {

    private final Map<OpenPgpFingerprint, CertSynopsis> nodes;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> edges;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges;
    private final ReferenceTime referenceTime;

    public Network(Map<OpenPgpFingerprint, CertSynopsis> nodes,
                   Map<OpenPgpFingerprint, List<CertificationSet>> edges,
                   Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges,
                   ReferenceTime referenceTime) {
        this.nodes = nodes;
        this.edges = edges;
        this.reverseEdges = reverseEdges;
        this.referenceTime = referenceTime;
    }

    /**
     * Create an empty {@link Network}.
     *
     * @param referenceTime reference time for evaluation
     * @return network
     */
    public static Network empty(@Nonnull ReferenceTime referenceTime) {
        return new Network(
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                referenceTime);
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
            Iterable<PGPPublicKeyRing> certificates,
            Policy policy,
            Optional<ReferenceTime> optReferenceTime) {
        ReferenceTime referenceTime = optReferenceTime.isPresent() ? optReferenceTime.get() : ReferenceTime.now();
        List<KeyRingInfo> validCerts = new ArrayList<>();
        for (PGPPublicKeyRing cert : certificates) {
            KeyRingInfo info = new KeyRingInfo(cert, policy, referenceTime.getTimestamp());
            if (info.getValidUserIds().isEmpty()) {
                // Ignore invalid cert
            } else {
                validCerts.add(info);
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
            //noinspection Java8MapApi
            if (byFingerprint.get(cert.getFingerprint()) == null) {
                byFingerprint.put(cert.getFingerprint(), cert);
            }
            List<KeyRingInfo> byKeyIdEntry = byKeyId.get(cert.getKeyId());

            //noinspection Java8MapApi
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

    public Map<OpenPgpFingerprint, CertSynopsis> getNodes() {
        return new HashMap<>(nodes);
    }

    public Map<OpenPgpFingerprint, List<CertificationSet>> getEdges() {
        return new HashMap<>(edges);
    }

    public Map<OpenPgpFingerprint, List<CertificationSet>> getReverseEdges() {
        return new HashMap<>(reverseEdges);
    }

    public ReferenceTime getReferenceTime() {
        return referenceTime;
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
}
