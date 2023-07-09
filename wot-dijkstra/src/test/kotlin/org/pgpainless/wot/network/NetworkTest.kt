// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import org.pgpainless.wot.network.Network.Companion.empty
import org.pgpainless.wot.network.ReferenceTime.Companion.now
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NetworkTest: NetworkDSL {

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
    fun `verify that setting referenceTime works`() {
        val ref = now()
        val network = buildNetwork {
            setReferenceTime(ref)
        }

        assertEquals(ref, network.referenceTime)
    }

    @Test
    fun `verify that adding a single node works`() {
        val network = buildNetwork { addNode("A") }

        assertEquals(1, network.nodes.size)
        assertTrue { network.nodes.containsKey(Fingerprint("A")) }
    }

    @Test
    fun `verify that adding multiple, non-connected nodes works`() {
        val network = buildNetwork { addNodes("A", "B", "C", "D") }
        assertEquals(4, network.nodes.size)
    }

    @Test
    fun testSimpleNetwork() {
        val network = buildNetwork {
            buildEdge("A", "B")
            buildEdge("A", "C", "Charlie <charlie@example.org>")
        }

        assertEquals("Network with 3 nodes, 2 edges:\n" +
                "A certifies binding: null <-> B [120]\n" +
                "A certifies binding: Charlie <charlie@example.org> <-> C [120]\n",
                network.toString())
    }

    @Test
    fun `verify that network with 2 edges between 2 nodes keeps edges`() {
        val network = buildNetwork {
            buildEdge("A", "B")
            buildEdge("A", "B", "Bob")
        }

        assertEquals(2, network.numberOfSignatures)
    }

    @Test
    fun `play with depths, amounts and regexes`() {
        val network = buildNetwork {
            buildEdge("A", "B", 120, 10)
            buildEdge("B", "C", 60, 5, RegexSet.fromExpression("*"))
            buildEdge("A", "C", 10, 0)
        }

        assertEquals(3, network.nodes.size)
        assertEquals(3, network.numberOfEdges)
        assertEquals(3, network.numberOfSignatures)

        assertEquals(120, network.getEdgeFor("A", "B")!!.first().trustAmount)
        assertEquals(10, network.getEdgeFor("A", "B")!!.first().trustDepth.value())
    }
}