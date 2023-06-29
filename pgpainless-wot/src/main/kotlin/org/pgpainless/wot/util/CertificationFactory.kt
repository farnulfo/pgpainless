// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.util

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.wot.dijkstra.sq.CertSynopsis
import org.pgpainless.wot.dijkstra.sq.Certification
import org.pgpainless.wot.dijkstra.sq.Depth
import org.pgpainless.wot.dijkstra.sq.RegexSet
import org.pgpainless.wot.dijkstra.sq.RegexSet.Companion.fromExpressionList

class CertificationFactory {

    companion object {
        @JvmStatic
        fun fromDelegation(issuer: CertSynopsis,
                           target: CertSynopsis,
                           signature: PGPSignature): Certification {
            return fromSignature(issuer, target, null, signature)
        }

        @JvmStatic
        fun fromCertification(issuer: CertSynopsis,
                              target: CertSynopsis,
                              targetUserId: String,
                              signature: PGPSignature): Certification {
            return fromSignature(issuer, target, targetUserId, signature)
        }

        @JvmStatic
        fun fromSignature(issuer: CertSynopsis,
                          target: CertSynopsis,
                          targetUserId: String?,
                          signature: PGPSignature): Certification {
            return Certification(
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