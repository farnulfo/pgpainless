// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.util

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.EdgeComponent
import org.pgpainless.wot.network.Depth
import org.pgpainless.wot.network.RegexSet
import org.pgpainless.wot.network.RegexSet.Companion.fromExpressionList

class CertificationFactory {

    companion object {
        @JvmStatic
        fun fromDelegation(issuer: Node,
                           target: Node,
                           signature: PGPSignature): EdgeComponent {
            return fromSignature(issuer, target, null, signature)
        }

        @JvmStatic
        fun fromCertification(issuer: Node,
                              target: Node,
                              targetUserId: String,
                              signature: PGPSignature): EdgeComponent {
            return fromSignature(issuer, target, targetUserId, signature)
        }

        @JvmStatic
        fun fromSignature(issuer: Node,
                          target: Node,
                          targetUserId: String?,
                          signature: PGPSignature): EdgeComponent {
            if (signature.signatureType == SignatureType.CERTIFICATION_REVOCATION.code) {
                // Revocations equate to trust of 0/0
                return EdgeComponent(
                        issuer,
                        target,
                        targetUserId,
                        SignatureSubpacketsUtil.getSignatureCreationTime(signature)!!.time,
                        SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature),
                        SignatureSubpacketsUtil.isExportable(signature),
                        0,
                        Depth.limited(0),
                        regexSetFrom(signature))
            } else {
                return EdgeComponent(
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