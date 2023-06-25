// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.util.Date;

public class Certification {

    private final CertSynopsis issuer;
    private final CertSynopsis target;
    private final Optional<String> userId;

    private final Date creationTime;
    private final Optional<Date> expirationTime;
    private final boolean exportable;
    private final int trustAmount;
    private final Depth trustDepth;
    private final RegexSet regex;

    public Certification(
            CertSynopsis issuer,
            CertSynopsis target,
            Optional<String> userId,
            Date creationTime,
            Optional<Date> expirationTime,
            boolean exportable,
            int trustAmount,
            Depth trustDepth,
            RegexSet regex) {
        this.issuer = issuer;
        this.target = target;
        this.userId = userId;
        this.creationTime = creationTime;
        this.expirationTime = expirationTime;
        this.exportable = exportable;
        this.trustAmount = trustAmount;
        this.trustDepth = trustDepth;
        this.regex = regex;
    }

    public Certification(CertSynopsis issuer,
                         Optional<String> targetUserId,
                         CertSynopsis target,
                         Date creationTime) {
        this.issuer = issuer;
        this.target = target;
        this.userId = targetUserId;
        this.creationTime = creationTime;

        this.expirationTime = Optional.empty();
        this.exportable = true;
        this.trustDepth = Depth.limited(0);
        this.trustAmount = 120;
        this.regex = RegexSet.wildcard();
    }

    /**
     * Get the issuer of the certification.
     *
     * @return issuer
     */
    public CertSynopsis getIssuer() {
        return issuer;
    }

    /**
     * Get the target of the certification.
     *
     * @return target
     */
    public CertSynopsis getTarget() {
        return target;
    }

    /**
     * Get the target user-id.
     *
     * @return user-id
     */
    public Optional<String> getUserId() {
        return userId;
    }

    /**
     * Get the creation time of the certification.
     *
     * @return creation time
     */
    public Date getCreationTime() {
        return creationTime;
    }

    /**
     * Get the (optional) expiration time of the certification.
     *
     * @return optional expiration time
     */
    public Optional<Date> getExpirationTime() {
        return expirationTime;
    }

    /**
     * Return true if the certification is marked as exportable.
     *
     * @return exportable
     */
    public boolean isExportable() {
        return exportable;
    }

    /**
     * Get the trust amount of the certification.
     *
     * @return trust amount
     */
    public int getTrustAmount() {
        return trustAmount;
    }

    /**
     * Get the trust depth of the certification.
     *
     * @return trust depth
     */
    public Depth getTrustDepth() {
        return trustDepth;
    }

    /**
     * Return the set of regular expressions.
     *
     * @return regex set
     */
    public RegexSet getRegexes() {
        return regex;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(issuer.getFingerprint()).append((issuer.userIds().isEmpty() ? " " : " (" + issuer.userIds().iterator().next() + ") "));
        sb.append(userId.isPresent() ? "certifies" : "delegates to").append(userId.isPresent() ? " [" + userId.get() + "] " : " ").append(target.getFingerprint())
                .append(userId.isEmpty() && !target.userIds().isEmpty() ? " (" + target.userIds().iterator().next() + ")" : "");
        return sb.toString();
    }
}
