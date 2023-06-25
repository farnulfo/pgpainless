// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class NetworkTest {

    @Test
    public void testEmptyNetworkIsEmpty() {
        ReferenceTime referenceTime = ReferenceTime.now();
        Network network = Network.empty(referenceTime);

        assertTrue(network.getNodes().isEmpty());
        assertTrue(network.getEdges().isEmpty());
        assertTrue(network.getReverseEdges().isEmpty());
        assertEquals(referenceTime, network.getReferenceTime());
    }

}
