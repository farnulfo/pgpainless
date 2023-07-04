// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

class Fingerprint(fingerprint: String) : Comparable<Fingerprint> {

    val fingerprint: String

    init {
        this.fingerprint = fingerprint.uppercase()
    }

    override fun compareTo(other: Fingerprint): Int {
        return fingerprint.compareTo(other.fingerprint)
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