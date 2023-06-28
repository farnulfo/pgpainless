// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import org.pgpainless.algorithm.RevocationState
import org.pgpainless.key.OpenPgpFingerprint
import java.util.*

/**
 * A [CertSynopsis] is a proxy object containing information about a certificate.
 *
 * @param fingerprint [OpenPgpFingerprint] of the certificate
 * @param expirationTime optional expiration time of the certificate
 * @param revocationState [RevocationState] denoting whether the certificate is revoked or not
 * @param userIds [Map] of user-ids on the certificate, along with their revocation states
 */
data class CertSynopsis(
        val fingerprint: OpenPgpFingerprint,
        val expirationTime: Date?,
        val revocationState: RevocationState,
        val userIds : Map<String, RevocationState>) {

    override fun toString(): String {
        return if (userIds.isEmpty()) {
            "$fingerprint"
        } else {
            "$fingerprint (${userIds.keys.first()})"
        }
    }
}