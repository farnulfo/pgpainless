// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import java.util.*

/**
 * An [EdgeComponent] represents a signature issued by one certificate over a datum on another target certificate.
 * Such a datum could be either a user-id, or the primary key of the target certificate.
 *
 * @param issuer certificate that issued the signature
 * @param target certificate that is target of this signature
 * @param userId optional user-id. If this is null, the signature is made over the primary key of the target.
 * @param creationTime creation time of the signature
 * @param expirationTime optional expiration time of the signature
 * @param exportable if false, the signtaure is marked as "not exportable"
 * @param trustAmount amount of trust the issuer places in the binding
 * @param trustDepth degree to which the issuer trusts the target as trusted introducer
 * @param regexes regular expressions for user-ids which the target is allowed to introduce
 */
data class EdgeComponent(
        val issuer: Node,
        val target: Node,
        val userId: String?,
        val creationTime: Date,
        val expirationTime: Date?,
        val exportable: Boolean,
        val trustAmount: Int,
        val trustDepth: Depth,
        val regexes: RegexSet
) {

    /**
     * Construct an [EdgeComponent] with default values. The result is non-expiring, will be exportable and has a
     * trust amount of 120, a depth of 0 and a wildcard regex.
     *
     * @param issuer certificate that issued the signature
     * @param target certificate that is target of this signature
     * @param targetUserId optional user-id. If this is null, the signature is made over the primary key of the target.
     * @param creationTime creation time of the signature
     */
    constructor(
            issuer: Node,
            target: Node,
            targetUserId: String? = null,
            creationTime: Date) :
            this(issuer, target, targetUserId, creationTime, null, true, 120, Depth.limited(0), RegexSet.wildcard())

    override fun toString(): String {
        return if (trustDepth.limit == 0)
            "${issuer.fingerprint} certifies binding: $userId <-> ${target.fingerprint} [$trustAmount]"
        else {
            val scope = if (regexes.regexStrings.isEmpty()) "" else ", scope: $regexes"
            "${issuer.fingerprint} delegates to ${target.fingerprint} [$trustAmount, depth $trustDepth$scope]"
        }
    }
}