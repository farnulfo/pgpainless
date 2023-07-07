// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

/**
 * A network consists of nodes, and edges between them.
 * For the Web of Trust, nodes consist of [CertSynopses][CertSynopsis], while the edges between the nodes are
 * [CertificationSets][CertificationSet].
 *
 * @constructor creates a new network
 * @param nodes contains a [Map] of [CertSynopsis] keyed by their [Fingerprint]
 * @param edges [Map] keyed by the [fingerprint][Fingerprint] of an issuer, whose values are [Lists][List] containing all edges originating from the issuer.
 * @param reverseEdges [Map] keyed by the [fingerprint][Fingerprint] of a target, whose values are [Lists][List] containing all edges pointing to the target
 * @param referenceTime reference time at which the [Network] was built
 */
class Network(
        val nodes: Map<Fingerprint, CertSynopsis>,
        val edges: Map<Fingerprint, List<CertificationSet>>,
        val reverseEdges: Map<Fingerprint, List<CertificationSet>>,
        val referenceTime: ReferenceTime) {

    companion object {
        @JvmStatic
        fun empty(referenceTime: ReferenceTime): Network {
            return Network(HashMap(), HashMap(), HashMap(), referenceTime)
        }

        @JvmStatic
        fun builder(): Builder {
            return Builder()
        }
    }

    /**
     * The total number of edges on the network.
     *
     * @return number of edges
     */
    val numberOfEdges: Int
        get() {
            return edges.values.sumOf { it.size }
        }

    /**
     * The total number of signatures the network comprises.
     */
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
                sb.appendLine(edge)
            }
        }
        return sb.toString()
    }

    class Builder internal constructor() {
        val nodes: MutableMap<Fingerprint, CertSynopsis> = mutableMapOf()
        private val protoEdges: MutableMap<Pair<Fingerprint, Fingerprint>, CertificationSet> = mutableMapOf()
        private var referenceTime: ReferenceTime = ReferenceTime.now()

        fun addNode(node: CertSynopsis): Builder {
            nodes[node.fingerprint] = node
            return this
        }

        fun getNode(fingerprint: Fingerprint): CertSynopsis? {
            return nodes[fingerprint]
        }

        fun addEdge(edge: Certification): Builder {
            protoEdges.getOrPut(Pair(edge.issuer.fingerprint, edge.target.fingerprint)) {
                CertificationSet.empty(edge.issuer, edge.target)
            }.add(edge)
            return this
        }

        fun setReferenceTime(time: ReferenceTime): Builder {
            this.referenceTime = time
            return this
        }

        fun build(): Network {
            val edges = mutableMapOf<Fingerprint, MutableList<CertificationSet>>()
            val revEdges = mutableMapOf<Fingerprint, MutableList<CertificationSet>>()

            protoEdges.forEach { (pair, certificationSet) ->
                edges.getOrPut(pair.first) {
                    mutableListOf()
                }.add(certificationSet)

                revEdges.getOrPut(pair.second) {
                    mutableListOf()
                }.add(certificationSet)
            }

            return Network(nodes, edges, revEdges, referenceTime)
        }
    }
}