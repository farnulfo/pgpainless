// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*

/**
 * A [Certification] is a signature issued by one certificate over a datum on another target certificate.
 * Such a datum could be either a user-id, or the primary key of the target certificate.
 *
 * @param issuer synopsis of the certificate that issued the [Certification]
 * @param target synopsis of the certificate that is target of this [Certification]
 * @param userId optional user-id. If this is null, the [Certification] is made over the primary key of the target.
 * @param creationTime creation time of the [Certification]
 * @param expirationTime optional expiration time of the [Certification]
 * @param exportable if false, the certification is marked as "not exportable"
 * @param trustAmount amount of trust the issuer places in the binding
 * @param trustDepth degree to which the issuer trusts the target as trusted introducer
 * @param regexes regular expressions for user-ids which the target is allowed to introduce
 */
data class Certification(
        val issuer: CertSynopsis,
        val target: CertSynopsis,
        val userId: String?,
        val creationTime: Date,
        val expirationTime: Date?,
        val exportable: Boolean,
        val trustAmount: Int,
        val trustDepth: Depth,
        val regexes: RegexSet
) {

    /**
     * Construct a [Certification] with default values. The result is non-expiring, will be exportable and has a
     * trust amount of 120, a depth of 0 and a wildcard regex.
     *
     * @param issuer synopsis of the certificate that issued the [Certification]
     * @param target synopsis of the certificate that is target of this [Certification]
     * @param targetUserId optional user-id. If this is null, the [Certification] is made over the primary key of the target.
     * @param creationTime creation time of the [Certification]
     */
    constructor(
            issuer: CertSynopsis,
            targetUserId: String?,
            target: CertSynopsis,
            creationTime: Date) :
            this(issuer, target, targetUserId, creationTime, null, true, 120, Depth.limited(0), RegexSet.wildcard())

    override fun toString(): String {
        return if (userId != null)
            "$issuer certifies [$userId] ${target.fingerprint}"
        else
            "$issuer delegates to ${target.fingerprint}"
    }
}