// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*

data class Certification(
        val issuer: CertSynopsis,
        val target: CertSynopsis,
        val userId: String?,
        val creationTime: Date,
        val expirationTime: Date?,
        val exportable: Boolean,
        val trustAmount: Int,
        val trustDepth: Depth,
        val regex: RegexSet
) {

    constructor(
            issuer: CertSynopsis,
            targetUserId: String?,
            target: CertSynopsis,
            creationTime: Date) :
            this(issuer, target, targetUserId, creationTime, null, true, 120, Depth.limited(0), RegexSet.wildcard())

    override fun toString(): String {
        val relation = if (userId != null) {
            "certifies"
        } else {
            "delegates to"
        }
        val relationTarget = if (userId != null) {
            "[$userId] ${target.fingerprint}"
        } else {
            "$target"
        }
        return "$issuer $relation $relationTarget"
    }
}