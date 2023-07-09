// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query.filter

import org.pgpainless.wot.network.EdgeComponent
import org.pgpainless.wot.network.Depth
import org.pgpainless.wot.network.RegexSet

/**
 * Current effective values for `depth`, `amount` and `regexps`.
 *
 * `regexps` is optional:
 * Rewriting the regular expressions may be expensive. By setting regexps to
 * `null`, the caller can signal that it doesn't care about the regular expressions.
 */
data class FilterValues(var depth: Depth, var amount: Int, var regexps: RegexSet?)

/**
 * A mechanism to filter certifications.
 *
 * This function should change the content of `values` in place.
 * This enables chaining of multiple filters.
 *
 * This is particularly useful when evaluating a residual network,
 * i.e., a network minus the capacity used by a particular path.
 */
interface CertificationFilter {

    /**
     * Filter the certification's parameters.
     *
     * If the function returns `false`, the certification should be skipped.
     */
    fun cost(c: EdgeComponent, values: FilterValues, ignoreRegexps: Boolean): Boolean {
        return true
    }

}
