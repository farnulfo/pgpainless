// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.Network.Companion.empty
import org.pgpainless.wot.dijkstra.sq.ReferenceTime.Companion.now
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
}