// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import kotlin.test.Test

class CostTest {

    @Test
    fun cost() {
        val cost1 = Cost(1, 60)
        val cost2 = Cost(1, 120)

        val cost3 = Cost(2, 60)
        val cost4 = Cost(2, 120)

        assert(cost1 > cost2) // cost2 is "cheaper": it constrains the amount of the path less
        assert(cost1 < cost3) // cost2 is "cheaper": it costs fewer hops

        assert(cost2 < cost3)
        assert(cost3 > cost4)

        assert(cost1 < cost4) // cost1 is "cheaper": even though it constrains the amount more, it costs fewer hops
        assert(cost2 < cost4)
    }

}