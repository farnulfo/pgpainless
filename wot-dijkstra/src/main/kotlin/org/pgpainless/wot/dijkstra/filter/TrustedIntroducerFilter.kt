// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.filter

import org.pgpainless.wot.dijkstra.sq.Certification
import org.pgpainless.wot.dijkstra.sq.Depth

/**
 * A filter that treats every certification as a trust signature with unconstrained depth,
 * and no regular expressions.
 *
 * Note: this filter doesn't change the trust amount.
 *
 * This filter can be used to view a network as a 'certification network'.
 */
class TrustedIntroducerFilter : CertificationFilter {
    override fun cost(c: Certification, values: FilterValues, ignoreRegexps: Boolean): Boolean {
        values.depth = Depth.unconstrained()
        if (!ignoreRegexps) {
            values.regexps = null
        }

        return true
    }
}
