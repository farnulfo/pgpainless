// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.query.Cost
import kotlin.test.Test

class CostTest {

    @Test
    fun cost() {
        val cost1 = Cost(1, 60)
        val cost2 = Cost(1, 120)

        val cost3 = Cost(2, 60)
        val cost4 = Cost(2, 120)

        assert(cost1 < cost2)
        assert(cost1 > cost3)

        assert(cost2 > cost3)
        assert(cost3 < cost4)

        assert(cost1 > cost4)
        assert(cost2 > cost4)
    }

}