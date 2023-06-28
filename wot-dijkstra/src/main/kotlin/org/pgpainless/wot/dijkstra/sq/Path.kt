// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import kotlin.math.min

class Path(
        val root: CertSynopsis,
        val edges: MutableList<Certification>,
        var residualDepth: Depth
) {
    constructor(root: CertSynopsis) : this(
            root, mutableListOf<Certification>(), Depth.unconstrained())

    val target: CertSynopsis
        get() {
            return if (edges.isEmpty()) {
                root
            } else {
                edges[edges.size - 1].target
            }
        }

    val certificates: List<CertSynopsis>
        get() {
            val certs: MutableList<CertSynopsis> = ArrayList()
            certs.add(root)
            for (certification in edges) {
                certs.add(certification.target)
            }
            return certs
        }

    val length: Int
        get() = edges.size + 1

    val certifications: List<Certification>
        get() = ArrayList(edges)

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

    fun append(certification: Certification) {
        require(target.fingerprint == certification.issuer.fingerprint) {
            "Cannot append certification to path: Path's tail is not issuer of the certification."
        }
        require(residualDepth.isUnconstrained() || residualDepth.limit!! > 0) {
            "Not enough depth."
        }

        var cyclic = root.fingerprint == certification.target.fingerprint
        for (i in 0..edges.size) {
            val edge = edges[i]
            if (cyclic) {
                break
            }
            if (edge.target.fingerprint == certification.target.fingerprint) {
                cyclic = if (i == edges.size - 1) {
                    edge.userId == certification.userId
                } else {
                    true
                }
            }
        }
        require(!cyclic) { "Adding the certification to the path would create a cycle." }

        residualDepth = certification.trustDepth.min(residualDepth.decrease(1))
        edges.add(certification)
    }
}