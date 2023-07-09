// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

/**
 * A network consists of nodes, and edges between them.
 * For the Web of Trust, a [Node] is a certificate, while the [Edges][Edge] between them are sets of signatures
 * ([EdgeComponent]).
 *
 * @constructor creates a new network
 * @param nodes contains a [Map] of [Node] keyed by their [Fingerprint]
 * @param edges [Edges][Edges] keyed by origin
 * @param reverseEdges [Edges][Edge] keyed by target
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
     * The total number of [Edges][Edge] on the network.
     *
     * @return number of edges
     */
    val numberOfEdges: Int
        get() {
            return edges.values.sumOf { it.size }
        }

    /**
     * The total number of signatures ([EdgeComponents][EdgeComponent]) the network comprises.
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
        private val protoEdges: MutableMap<Pair<Fingerprint, Fingerprint>, Edge> = mutableMapOf()
        private var referenceTime: ReferenceTime = ReferenceTime.now()

        fun addNode(node: Node): Builder {
            nodes[node.fingerprint] = node
            return this
        }

        fun getNode(fingerprint: Fingerprint): Node? {
            return nodes[fingerprint]
        }

        fun addEdge(edge: EdgeComponent): Builder {
            protoEdges.getOrPut(Pair(edge.issuer.fingerprint, edge.target.fingerprint)) {
                Edge.empty(edge.issuer, edge.target)
            }.add(edge)
            return this
        }

        fun setReferenceTime(time: ReferenceTime): Builder {
            this.referenceTime = time
            return this
        }

        fun build(): Network {
            val edges = mutableMapOf<Fingerprint, MutableList<Edge>>()
            val revEdges = mutableMapOf<Fingerprint, MutableList<Edge>>()

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