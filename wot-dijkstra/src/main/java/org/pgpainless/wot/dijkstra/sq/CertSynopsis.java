// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import org.pgpainless.algorithm.RevocationState;
import org.pgpainless.key.OpenPgpFingerprint;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class CertSynopsis {

    private final OpenPgpFingerprint fingerprint;
    private final Date expirationTime;
    private final RevocationState revocationState;
    private final Set<String> userIds;

    /**
     * Create a new {@link CertSynopsis}.
     *
     * @param fingerprint fingerprint of the certificate
     * @param expirationTime expiration time
     * @param revocationState revocation state of the certificate
     * @param userIds set of user-ids
     */
    public CertSynopsis(OpenPgpFingerprint fingerprint,
                        Date expirationTime,
                        RevocationState revocationState,
                        Set<String> userIds) {
        this.fingerprint = fingerprint;
        this.expirationTime = expirationTime;
        this.revocationState = revocationState;
        this.userIds = userIds;
    }

    /**
     * Return the fingerprint of the certificate.
     *
     * @return fingerprint
     */
    public OpenPgpFingerprint getFingerprint() {
        return fingerprint;
    }

    /**
     * Get the certificates expiration time.
     *
     * @return expiration time
     */
    public Date getExpirationTime() {
        return expirationTime;
    }

    /**
     * Get the revocation status of the certificate.
     *
     * @return revocation state
     */
    public RevocationState getRevocationState() {
        return revocationState;
    }

    /**
     * Get a {@link Set} containing all user-ids of the certificate.
     *
     * @return user-ids
     */
    public Set<String> userIds() {
        return new HashSet<>(userIds);
    }
}
