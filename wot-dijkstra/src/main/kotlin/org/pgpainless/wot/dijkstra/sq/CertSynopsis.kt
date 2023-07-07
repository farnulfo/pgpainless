// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*

/**
 * A [CertSynopsis] is a proxy object containing information about a certificate.
 *
 * @param fingerprint [Fingerprint] of the certificate
 * @param expirationTime optional expiration time of the certificate
 * @param revocationState [RevocationState] denoting whether the certificate is revoked or not
 * @param userIds [Map] of user-ids on the certificate, along with their revocation states
 */
data class CertSynopsis(
        val fingerprint: Fingerprint,
        val expirationTime: Date? = null,
        val revocationState: RevocationState = RevocationState.notRevoked(),
        val userIds : Map<String, RevocationState> = mapOf()) {

    constructor(fingerprint: String,
            expirationTime: Date? = null,
            revocationState: RevocationState = RevocationState.notRevoked(),
            userIds: Map<String, RevocationState> = mapOf()):
            this(Fingerprint(fingerprint), expirationTime, revocationState, userIds)

    override fun toString(): String {
        return if (userIds.isEmpty()) {
            "$fingerprint"
        } else {
            "$fingerprint (${userIds.keys.first()})"
        }
    }
}