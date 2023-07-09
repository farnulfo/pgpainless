// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

/**
 * List of individual [Paths][Path].
 *
 * @param _paths list of paths
 */
class Paths(private val _paths: MutableList<Item>) {

    /**
     * Empty collection of paths.
     */
    constructor(): this(mutableListOf<Item>())

    val paths: List<Path>
        get() {
            return _paths.map { it.path }
        }

    /**
     * Add a [Path] to the list.
     *
     * @throws IllegalArgumentException if the given amount is smaller or equal to the paths trust amount.
     */
    fun add(path: Path, amount: Int) {
        require(amount <= path.amount) {
            "Amount too small. TODO: Better error message"
        }
        _paths.add(Item(path, amount))
    }

    /**
     * The summed trust amount of all paths in this collection.
     */
    val amount: Int
        get() {
            return _paths.sumOf { it.amount }
        }

    /**
     * @param path path
     * @param amount trust amount
     */
    data class Item(val path: Path, val amount: Int) {
        override fun toString(): String {
            return "$path ($amount)"
        }
    }
}