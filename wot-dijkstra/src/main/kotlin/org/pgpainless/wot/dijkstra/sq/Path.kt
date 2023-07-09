// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import kotlin.math.min

/**
 * A [Path] comprises a root [Node], a list of edgeSet ([Certifications][Edge]), as well as a
 * residual depth.
 *
 * @param root root of the path
 * @param edges list of edgeSet from the root to the target
 * @param residualDepth residual depth that is decreased each time another edge is appended
 */
class Path(
        val root: Node,
        private val edges: MutableList<Edge>,
        var residualDepth: Depth
) {

    /**
     * Construct a [Path] only consisting of the trust root.
     * The [Path] will have an empty list of edgeSet and an unconstrained residual [Depth].
     *
     * @param root trust root
     */
    constructor(root: Node) : this(
            root, mutableListOf<Edge>(), Depth.unconstrained())

    /**
     * Current target of the path.
     * This corresponds to the target of the last entry in the edge list.
     */
    val target: Node
        get() {
            return if (edges.isEmpty()) {
                root
            } else {
                edges.last().target
            }
        }

    /**
     * List of [CertSynopses][Node] (nodes) of the path.
     * The first entry is the [root]. The other entries are the targets of the edgeSet.
     */
    val certificates: List<Node>
        get() {
            val certs: MutableList<Node> = mutableListOf(root)
            for (certification in edges) {
                certs.add(certification.target)
            }
            return certs
        }

    /**
     * The length of the path, counted in nodes.
     * A path with a single edge between node A and B has length 2, the empty path with only a trust root has length 1.
     */
    val length: Int
        get() = edges.size + 1

    /**
     * List of edgeSet.
     */
    val certifications: List<Edge>
        get() = edges.toList()

    /**
     * Trust amount of the path.
     * This corresponds to the smallest trust amount of any edge in the path.
     */
    val amount: Int
        get() = if (edges.isEmpty()) {
            120
        } else {
            var min = 255
            for (edge in edges) {
                min = min(min, edge.trustAmount)
            }
            min
        }

    /**
     * Append an edge to the path and decrease the [residualDepth] of the path by 1.
     *
     * @throws IllegalArgumentException if the target at the end of the path is not equal to the issuer of the edge.
     * @throws IllegalArgumentException if the path runs out of residual depth
     * @throws IllegalArgumentException if the addition of the [Edge] would result in a cyclic path
     */
    fun append(aEdge: Edge) {
        require(target.fingerprint == aEdge.issuer.fingerprint) {
            "Cannot append edge to path: Path's tail is not issuer of the edge."
        }
        require(residualDepth.isUnconstrained() || residualDepth.limit!! > 0) {
            "Not enough depth."
        }

        // root is c's target -> illegal cycle
        var cyclic = root.fingerprint == aEdge.target.fingerprint
        for ((i, edge) in edges.withIndex()) {
            if (cyclic) {
                break
            }
            // existing edge points to c's target -> illegal cycle
            if (aEdge.target.fingerprint == edge.target.fingerprint) {
                cyclic = if (edges.lastIndex != i) {
                    // Cycle in the middle of the ~~street~~ path
                    true
                } else {
                    // Not a cycle, if we point to a different user-id
                    aEdge.userId == edge.userId
                }
            }
        }
        require(!cyclic) { "Adding the edge to the path would create a cycle." }

        residualDepth = aEdge.trustDepth.min(residualDepth.decrease(1))
        edges.add(aEdge)
    }

    override fun toString(): String {
        return "{${root.fingerprint}} => {${edges.map { it.target }.joinToString(" -> ")}} (residual {$residualDepth})"
    }
}