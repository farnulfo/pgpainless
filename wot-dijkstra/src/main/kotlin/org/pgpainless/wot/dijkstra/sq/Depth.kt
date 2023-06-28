// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

class Depth(val limit: Int?) : Comparable<Depth> {

    companion object {
        @JvmStatic
        fun unconstrained() : Depth {
            return Depth(null)
        }

        @JvmStatic
        fun limited(limit: Int): Depth {
            require(limit in 0..255) {
                "Trust depth MUST be a value between 0 and 255."
            }
            return Depth(limit)
        }

        @JvmStatic
        fun auto(limit: Int): Depth {
            return if (limit == 255) {
                unconstrained()
            } else {
                limited(limit)
            }
        }
    }

    fun isUnconstrained() : Boolean {
        return limit == null
    }

    fun decrease(value : Int) : Depth {
        return if (isUnconstrained()) {
            unconstrained()
        } else {
            if (limit!! >= value) {
                limited(limit - value)
            } else {
                throw IllegalArgumentException("Depth cannot be decreased.")
            }
        }
    }

    fun min(other: Depth) : Depth {
        return if (compareTo(other) <= 0) {
            this
        } else {
            other
        }
    }

    override fun compareTo(o: Depth): Int {
        return if (isUnconstrained()) {
            if (o.isUnconstrained()) {
                0
            } else {
                1
            }
        } else {
            if (o.isUnconstrained()) {
                -1
            } else {
                limit!!.compareTo(o.limit!!)
            }
        }
    }

    override fun toString() : String {
        return if (isUnconstrained()) { "unconstrained" } else { limit!!.toString() }
    }
}