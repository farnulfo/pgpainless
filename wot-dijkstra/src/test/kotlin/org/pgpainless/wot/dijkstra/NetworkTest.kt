// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.CertSynopsis
import org.pgpainless.wot.dijkstra.sq.Certification
import org.pgpainless.wot.dijkstra.sq.Network
import org.pgpainless.wot.dijkstra.sq.Network.Companion.empty
import org.pgpainless.wot.dijkstra.sq.ReferenceTime.Companion.now
import java.util.Date
import kotlin.test.assertEquals

class NetworkTest {

    @Test
    fun testEmptyNetworkIsEmpty() {
        val referenceTime = now()
        val network = empty(referenceTime)
        assert(network.nodes.isEmpty())
        assert(network.edges.isEmpty())
        assert(network.reverseEdges.isEmpty())
        assertEquals(referenceTime, network.referenceTime)
        assertEquals(0, network.numberOfEdges)
        assertEquals(0, network.numberOfSignatures)
    }

    @Test
    fun testSimpleNetwork() {
        val alice = CertSynopsis("A")
        val bob = CertSynopsis("B")

        val edge = Certification(alice, bob, null, Date())

        val network = Network.builder()
                .addNode(alice)
                .addNode(bob)
                .addEdge(edge)
                .build()

        println(network)
    }
}