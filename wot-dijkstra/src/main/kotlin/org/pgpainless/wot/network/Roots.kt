// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * A set of `Root`s (that can be used as the basis for authentication lookups).
 */
class Roots {

    // Map for efficient lookup by Fingerprint
    private val roots: Map<Fingerprint, Root>

    constructor(roots: List<Root>) {
        this.roots = roots.associateBy { it.fingerprint }
    }

    constructor() : this(listOf())

    /**
     * Returns the specified root.
     */
    fun get(fpr: Fingerprint): Root? = roots[fpr]

    /**
     * Check if `fpr` is contained in this set of roots.
     */
    fun isRoot(fpr: Fingerprint) = roots.containsKey(fpr)

    /**
     * The set of fingerprints of all roots.
     */
    fun fingerprints() = roots.keys

    /**
     * A collection of all roots.
     */
    fun roots() = roots.values

    /**
     * The number of roots
     */
    fun size() = roots.size

    override fun toString() = roots.keys.sorted().joinToString(", ")

}
