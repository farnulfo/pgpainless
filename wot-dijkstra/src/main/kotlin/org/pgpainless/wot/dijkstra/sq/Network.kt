// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import org.pgpainless.key.OpenPgpFingerprint

/**
 * A network consists of nodes, and edges between them.
 * For the Web of Trust, nodes consist of [CertSynopses][CertSynopsis], while the edges between the nodes are
 * [CertificationSets][CertificationSet].
 *
 * @constructor creates a new network
 * @param nodes contains a [Map] of [CertSynopsis] keyed by their [OpenPgpFingerprint]
 * @param edges [Map] keyed by the [fingerprint][OpenPgpFingerprint] of an issuer, whose values are [Lists][List] containing all edges originating from the issuer.
 * @param reverseEdges [Map] keyed by the [fingerprint][OpenPgpFingerprint] of a target, whose values are [Lists][List] containing all edges pointing to the target
 * @param referenceTime reference time at which the [Network] was built
 */
class Network(
        val nodes: Map<OpenPgpFingerprint, CertSynopsis>,
        val edges: Map<OpenPgpFingerprint, List<CertificationSet>>,
        val reverseEdges: Map<OpenPgpFingerprint, List<CertificationSet>>,
        val referenceTime: ReferenceTime) {

    companion object {
        @JvmStatic
        fun empty(referenceTime: ReferenceTime): Network {
            return Network(HashMap(), HashMap(), HashMap(), referenceTime)
        }
    }

    val numberOfEdges: Int
        get() {
            return edges.values.sumOf { it.size }
        }

    val numberOfSignatures: Int
        get() {
            return edges.values
                    .flatten()
                    .flatMap { it.certifications.values }
                    .sumOf { it.size }
        }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("Network with ${nodes.size} nodes, $numberOfEdges edges:\n")
        for (issuer in nodes.keys) {
            val outEdges = edges[issuer] ?: continue
            for (edge in outEdges) {
                sb.append(edge)
            }
        }
        return sb.toString()
    }
}