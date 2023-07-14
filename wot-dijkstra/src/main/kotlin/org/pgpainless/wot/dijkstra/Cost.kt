// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import kotlin.math.min

/**
 * A path's "cost".
 *
 * This Cost type is used for comparison in Dijkstra's algorithm.
 */
internal class Cost(
        // The path's length (i.e., the number of hops to the target).
        // *Less* length is "cheaper" (short paths require less "depth" in delegations).
        val length: Int,

        // The trust amount along this path.
        // Smaller trust amount is "more expensive"
        // (paths with a low trust amount are more constraining and thus less desirable).
        val amount: Int,
) : Comparable<Cost> {

    // "Smaller than" means: the path is "cheaper", and thus preferable:
    // - A small length (requiring fewer hops).
    // - For equal length: A higher "trust amount" (which is less constraining)
    override fun compareTo(other: Cost) =
            compareValuesBy(this, other, { it.length }, { -it.amount })

    override fun toString() = "length $length, amount $amount"

    /** Calculate the cost of a path,  when adding a new segment with trust amount `amount` */
    fun extendBy(amount: Int) = Cost(this.length + 1, min(amount, this.amount))

}