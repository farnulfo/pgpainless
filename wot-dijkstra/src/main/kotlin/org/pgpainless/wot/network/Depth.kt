// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * Depth of a trust signature.
 */
class Depth private constructor(private val limit: Int) : Comparable<Int> {

    // Uses a byte for internal representation, like in the OpenPGP "Trust Signature" subpacket

    companion object {
        /**
         * The target is trusted to an unlimited degree.
         */
        @JvmStatic
        fun unconstrained() = Depth(255)

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
            require(limit in 0..255) {
                "Trust depth MUST be a value between 0 and 255."
            }
            return Depth(limit)
        }
    }

    /**
     * Return true, if the [Depth] is unconstrained.
     */
    fun isUnconstrained() = limit == 255

    /**
     * The value of this Depth, as used in OpenPGP.
     *
     * Unlimited is 255.
     */
    fun value() = limit

    /**
     * Decrease the trust depth by `value` and return the result.
     * If the [Depth] is unconstrained, the result will still be unconstrained.
     * @throws IllegalArgumentException if the [Depth] cannot be decreased any further
     */
    fun decrease(value: Int): Depth {
        return if (isUnconstrained()) {
            unconstrained()
        } else {
            if (limit >= value) {
                limited(limit - value)
            } else {
                throw IllegalArgumentException("Depth cannot be decreased.")
            }
        }
    }

    /**
     * Return the minimum [Depth] of this and the other [Depth].
     */
    fun min(other: Depth): Depth {
        return if (limit > other.limit) {
            other
        } else {
            this
        }
    }

    override fun compareTo(other: Int): Int {
        return if (isUnconstrained()) {
            // If this is unconstrained, it is bigger than `other`
            1
        } else {
            limit.compareTo(other)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (other !is Depth) {
            return false
        }

        return limit == other.limit
    }

    override fun toString(): String {
        return if (isUnconstrained()) {
            "unconstrained"
        } else {
            limit.toString()
        }
    }

    override fun hashCode() = limit
}