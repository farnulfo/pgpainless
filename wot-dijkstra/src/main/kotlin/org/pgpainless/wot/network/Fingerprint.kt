// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

class Fingerprint(fingerprint: String) : Comparable<Fingerprint> {

    val fingerprint: String

    init {
        this.fingerprint = fingerprint.uppercase()
    }

    override fun compareTo(other: Fingerprint): Int {
        // The strings are equal
        if (this == other) return 0

        // Compare char by char.
        // This ordering has the property that Hex-encoded Fingerprints are
        // ordered in the same way as in sequoia-wot.
        // (As they would be, if they were byte arrays).
        //
        // For other formats of "Fingerprint", the specific ordering doesn't matter to us.
        //
        // Following the sequoia-wot ordering means that we get the exact same output for the test suite.
        val a = this.fingerprint.toCharArray()
        val b = other.fingerprint.toCharArray()
        a.zip(b).forEach { (x, y) ->
            if (x != y) return x.compareTo(y)
        }

        // If prefix is the same, but one string is longer, we consider the longer one "bigger"
        if (a.size != b.size) return a.size.compareTo(b.size)

        throw RuntimeException("This should be unreachable")
    }

    override fun equals(other: Any?): Boolean {
        return other?.toString() == toString()
    }

    override fun hashCode(): Int {
        return toString().hashCode()
    }

    override fun toString(): String {
        return fingerprint.uppercase()
    }
}