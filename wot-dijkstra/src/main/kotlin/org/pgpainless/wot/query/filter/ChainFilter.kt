// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query.filter

import org.pgpainless.wot.network.EdgeComponent

/**
 * A filter that chains multiple filters together.
 *
 * The filters are called in the order that they are added. If a
 * filter returns `false`, then this filter immediately returns
 * false.
 */
class ChainFilter(val filters: MutableList<CertificationFilter>) : CertificationFilter {

    override fun cost(c: EdgeComponent, values: FilterValues, ignoreRegexps: Boolean): Boolean {

        // If any inner filter returns `false`, immediately return false
        return !this.filters.any { !it.cost(c, values, ignoreRegexps) }
    }
}
