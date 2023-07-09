// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.util

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.Edge
import org.pgpainless.wot.network.Depth
import org.pgpainless.wot.network.RegexSet
import org.pgpainless.wot.network.RegexSet.Companion.fromExpressionList

class CertificationFactory {

    companion object {
        @JvmStatic
        fun fromDelegation(issuer: Node,
                           target: Node,
                           signature: PGPSignature): Edge {
            return fromSignature(issuer, target, null, signature)
        }

        @JvmStatic
        fun fromCertification(issuer: Node,
                              target: Node,
                              targetUserId: String,
                              signature: PGPSignature): Edge {
            return fromSignature(issuer, target, targetUserId, signature)
        }

        @JvmStatic
        fun fromSignature(issuer: Node,
                          target: Node,
                          targetUserId: String?,
                          signature: PGPSignature): Edge {
            return Edge(
                    issuer,
                    target,
                    targetUserId,
                    SignatureSubpacketsUtil.getSignatureCreationTime(signature)!!.time,
                    SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature),
                    SignatureSubpacketsUtil.isExportable(signature),
                    getTrustAmountFrom(signature),
                    getTrustDepthFrom(signature),
                    regexSetFrom(signature))
        }

        @JvmStatic
        private fun getTrustAmountFrom(signature: PGPSignature): Int {
            val packet = SignatureSubpacketsUtil.getTrustSignature(signature)
            return packet?.trustAmount ?: 120
        }

        @JvmStatic
        private fun getTrustDepthFrom(signature: PGPSignature): Depth {
            val packet = SignatureSubpacketsUtil.getTrustSignature(signature)
            return if (packet != null) {
                Depth.auto(packet.depth)
            } else Depth.limited(0)
        }

        @JvmStatic
        private fun regexSetFrom(signature: PGPSignature): RegexSet {
            val regexList = SignatureSubpacketsUtil.getRegularExpressions(signature)
            val stringList: MutableList<String> = mutableListOf()
            regexList.mapTo(stringList) { it.regex }
            return fromExpressionList(stringList)
        }
    }
}