// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;

/**
 * A {@link CertificationSet} is a set of {@link Certification Certifications} made by the same issuer, on the same
 * target certificate.
 * In some sense, a {@link CertificationSet} can be considered an edge in the web of trust.
 */
public final class CertificationSet {

    private final CertSynopsis issuer;
    private final CertSynopsis target;

    private final Map<Optional<String>, List<Certification>> certifications;

    /**
     * Create an empty {@link CertificationSet}.
     *
     * @param issuer issuer
     * @param target target
     * @return empty set
     */
    public static CertificationSet empty(CertSynopsis issuer, CertSynopsis target) {
        return new CertificationSet(issuer, target, new HashMap<>());
    }

    public static CertificationSet fromCertification(Certification certification) {
        CertificationSet set = CertificationSet.empty(certification.getIssuer(), certification.getTarget());
        set.add(certification);
        return set;
    }

    private CertificationSet(CertSynopsis issuer,
                             CertSynopsis target,
                             Map<Optional<String>, List<Certification>> certifications) {
        this.issuer = issuer;
        this.target = target;
        this.certifications = new HashMap<>(certifications);
    }

    public CertSynopsis getIssuer() {
        return issuer;
    }

    public CertSynopsis getTarget() {
        return target;
    }

    public Map<Optional<String>, List<Certification>> getCertifications() {
        // Copy to avoid side effects
        Map<Optional<String>, List<Certification>> copy = new HashMap<>();
        for (Optional<String> key : certifications.keySet()) {
            copy.put(key, new ArrayList<>(certifications.get(key)));
        }
        return copy;
    }

    /**
     * Merge this {@link CertificationSet} with another instance.
     * After the operation, this will contain {@link Certification Certifications} from both sets.
     *
     * @param other other {@link CertificationSet}
     */
    public void merge(@Nonnull CertificationSet other) {
        if (other == this) {
            return;
        }

        if (!issuer.getFingerprint().equals(other.issuer.getFingerprint())) {
            throw new IllegalArgumentException("Issuer fingerprint mismatch.");
        }

        if (!target.getFingerprint().equals(other.target.getFingerprint())) {
            throw new IllegalArgumentException("Target fingerprint mismatch.");
        }

        for (Map.Entry<Optional<String>, List<Certification>> entry : other.certifications.entrySet()) {
            for (Certification certification : entry.getValue()) {
                add(certification);
            }
        }
    }

    /**
     * Add a {@link Certification} into this {@link CertificationSet}.
     *
     * @param certification certification
     */
    public void add(@Nonnull Certification certification) {
        if (!issuer.getFingerprint().equals(certification.getIssuer().getFingerprint())) {
            throw new IllegalArgumentException("Issuer fingerprint mismatch.");
        }
        if (!target.getFingerprint().equals(certification.getTarget().getFingerprint())) {
            throw new IllegalArgumentException("Target fingerprint mismatch.");
        }

        List<Certification> certificationsForUserId = certifications.get(certification.getUserId());
        // noinspection Java8MapApi
        if (certificationsForUserId == null) {
            certificationsForUserId = new ArrayList<>();
            certifications.put(certification.getUserId(), certificationsForUserId);
        }
        // TODO: Prevent duplicates, only keep newest timestamped sig?
        certificationsForUserId.add(certification);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Optional<String>, List<Certification>> entry : certifications.entrySet()) {
            for (Certification certification : entry.getValue()) {
                sb.append(certification).append('\n');
            }
        }
        return sb.toString();
    }
}
