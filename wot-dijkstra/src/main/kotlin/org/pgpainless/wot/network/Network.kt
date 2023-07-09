// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * A network consists of nodes, and edgeSet between them.
 * For the Web of Trust, nodes consist of [CertSynopses][Node], while the edgeSet between the nodes are
 * [CertificationSets][EdgeSet].
 *
 * @constructor creates a new network
 * @param nodes contains a [Map] of [Node] keyed by their [Fingerprint]
 * @param edgeSet [Map] keyed by the [fingerprint][Fingerprint] of an issuer, whose values are [Lists][List] containing all edgeSet originating from the issuer.
 * @param reverseEdgeSet [Map] keyed by the [fingerprint][Fingerprint] of a target, whose values are [Lists][List] containing all edgeSet pointing to the target
 * @param referenceTime reference time at which the [Network] was built
 */
class Network(
        val nodes: Map<Fingerprint, Node>,
        val edgeSet: Map<Fingerprint, List<EdgeSet>>,
        val reverseEdgeSet: Map<Fingerprint, List<EdgeSet>>,
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
     * The total number of edgeSet on the network.
     *
     * @return number of edgeSet
     */
    val numberOfEdges: Int
        get() {
            return edgeSet.values.sumOf { it.size }
        }

    /**
     * The total number of signatures the network comprises.
     */
    val numberOfSignatures: Int
        get() {
            return edgeSet.values
                    .flatten()
                    .flatMap { it.certifications.values }
                    .sumOf { it.size }
        }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("Network with ${nodes.size} nodes, $numberOfEdges edgeSet:\n")
        for (issuer in nodes.keys) {
            val outEdges = edgeSet[issuer] ?: continue
            for (edge in outEdges) {
                sb.appendLine(edge)
            }
        }
        return sb.toString()
    }

    class Builder internal constructor() {
        val nodes: MutableMap<Fingerprint, Node> = mutableMapOf()
        private val protoEdgeSet: MutableMap<Pair<Fingerprint, Fingerprint>, EdgeSet> = mutableMapOf()
        private var referenceTime: ReferenceTime = ReferenceTime.now()

        fun addNode(node: Node): Builder {
            nodes[node.fingerprint] = node
            return this
        }

        fun getNode(fingerprint: Fingerprint): Node? {
            return nodes[fingerprint]
        }

        fun addEdge(edge: Edge): Builder {
            protoEdgeSet.getOrPut(Pair(edge.issuer.fingerprint, edge.target.fingerprint)) {
                EdgeSet.empty(edge.issuer, edge.target)
            }.add(edge)
            return this
        }

        fun setReferenceTime(time: ReferenceTime): Builder {
            this.referenceTime = time
            return this
        }

        fun build(): Network {
            val edgeSet = mutableMapOf<Fingerprint, MutableList<EdgeSet>>()
            val revEdgeSet = mutableMapOf<Fingerprint, MutableList<EdgeSet>>()

            protoEdgeSet.forEach { (pair, certificationSet) ->
                edgeSet.getOrPut(pair.first) {
                    mutableListOf()
                }.add(certificationSet)

                revEdgeSet.getOrPut(pair.second) {
                    mutableListOf()
                }.add(certificationSet)
            }

            return Network(nodes, edgeSet, revEdgeSet, referenceTime)
        }
    }
}