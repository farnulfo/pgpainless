// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

class Paths(val paths: MutableList<Item>) {

    fun add(path: Path, amount: Int) {
        require(amount <= path.amount) {
            "Amount too small. TODO: Better error message"
        }
        paths.add(Item(path, amount))
    }

    val amount: Int
        get() {
            return paths.sumOf { it.amount }
        }

    data class Item(val path: Path, val amount: Int) {

    }
}