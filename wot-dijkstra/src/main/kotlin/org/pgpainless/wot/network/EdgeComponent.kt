// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import java.util.*

/**
 * An [EdgeComponent] is a signature issued by one certificate over a datum on another target certificate.
 * Such a datum could be either a user-id, or the primary key of the target certificate.
 *
 * @param issuer certificate that issued the [EdgeComponent]
 * @param target certificate that is target of this [EdgeComponent]
 * @param userId optional user-id. If this is null, the [EdgeComponent] is made over the primary key of the target.
 * @param creationTime creation time of the [EdgeComponent]
 * @param expirationTime optional expiration time of the [EdgeComponent]
 * @param exportable if false, the certification is marked as "not exportable"
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

    override fun toString(): String {
        return if (trustDepth > 0) {
            val scope = if (regexes.regexStrings.isEmpty()) "" else ", scope: $regexes"
            "${issuer.fingerprint} delegates to ${target.fingerprint} [$trustAmount, depth $trustDepth$scope]"
        } else {
            "${issuer.fingerprint} certifies binding: $userId <-> ${target.fingerprint} [$trustAmount]"
        }
    }
}