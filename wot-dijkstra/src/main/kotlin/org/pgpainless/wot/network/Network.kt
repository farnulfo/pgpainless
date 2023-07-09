// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * A network consists of nodes, and edges between them.
 * In the Web-of-Trust, a [Node] corresponds to a certificate, while an [Edge] comprises all [EdgeComponents][EdgeComponent]
 * (certifications) between two certificates, separated by their datum (e.g. the certified user-id).
 *
 * @constructor creates a new network
 * @param nodes associate [Nodes][Node] with their [Fingerprint]
 * @param edges map of [Edges][Edge] keyed by their issuers [Fingerprint]
 * @param reverseEdges map of [Edges][Edge] keyed by their targets [Fingerprint]
 * @param referenceTime reference time at which the [Network] was built
 */
class Network(
        val nodes: Map<Fingerprint, Node>,
        val edges: Map<Fingerprint, List<Edge>>,
        val reverseEdges: Map<Fingerprint, List<Edge>>,
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
     * The total number of individual [EdgeComponents][EdgeComponent] the network comprises.
     */
    val numberOfSignatures: Int
        get() {
            return edges.values
                    .flatten()
                    .flatMap { it.components.values }
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
        val nodes: MutableMap<Fingerprint, Node> = mutableMapOf()
        private val protoEdgeSet: MutableMap<Pair<Fingerprint, Fingerprint>, Edge> = mutableMapOf()
        private var referenceTime: ReferenceTime = ReferenceTime.now()

        fun addNode(node: Node): Builder {
            nodes[node.fingerprint] = node
            return this
        }

        fun getNode(fingerprint: Fingerprint): Node? {
            return nodes[fingerprint]
        }

        fun addEdge(edgeComponent: EdgeComponent): Builder {
            protoEdgeSet.getOrPut(Pair(edgeComponent.issuer.fingerprint, edgeComponent.target.fingerprint)) {
                Edge.empty(edgeComponent.issuer, edgeComponent.target)
            }.add(edgeComponent)
            return this
        }

        fun setReferenceTime(time: ReferenceTime): Builder {
            this.referenceTime = time
            return this
        }

        fun build(): Network {
            val edgeSet = mutableMapOf<Fingerprint, MutableList<Edge>>()
            val revEdgeSet = mutableMapOf<Fingerprint, MutableList<Edge>>()

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