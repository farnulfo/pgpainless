// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

/**
 * Depth of a trust signature.
 */
class Depth private constructor(val limit: Int?) : Comparable<Depth> {

    companion object {
        /**
         * The target is trusted to an unlimited degree.
         */
        @JvmStatic
        fun unconstrained() : Depth {
            return Depth(null)
        }

        /**
         * The target is trusted to a limited degree.
         */
        @JvmStatic
        fun limited(limit: Int): Depth {
            require(limit in 0..254) {
                "Trust depth MUST be a value between 0 and 254."
            }
            return Depth(limit)
        }

        /**
         * Deduce the trust degree automatically.
         */
        @JvmStatic
        fun auto(limit: Int): Depth {
            return if (limit == 255) {
                unconstrained()
            } else {
                limited(limit)
            }
        }
    }

    /**
     * Return true, if the [Depth] is unconstrained.
     */
    fun isUnconstrained() : Boolean {
        return limit == null
    }

    /**
     * The value of this Depth, as used in OpenPGP.
     *
     * Unlimited is 255.
     */
    fun value(): Int {
        return limit ?: 255
    }

    /**
     * Decrease the trust depth by one and return the result.
     * If the [Depth] is unconstrained, the result will still be unconstrained.
     * @throws IllegalArgumentException if the [Depth] cannot be decreased any further
     */
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

    /**
     * Return the minimum [Depth] of this and the other [Depth].
     */
    fun min(other: Depth) : Depth {
        return if (compareTo(other) <= 0) {
            this
        } else {
            other
        }
    }

    override fun compareTo(other: Depth): Int {
        return when (Pair(isUnconstrained(), other.isUnconstrained())) {
            Pair(true, true) -> 0
            Pair(true, false) -> 1
            Pair(false, true) -> -1
            else -> limit!!.compareTo(other.limit!!)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (other !is Depth) {
            return false
        }

        return limit == other.limit
    }

    override fun toString() : String {
        return if (isUnconstrained()) { "unconstrained" } else { limit!!.toString() }
    }

    override fun hashCode(): Int {
        return limit ?: 0 // TODO: 255?
    }
}