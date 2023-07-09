// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.filter

import org.pgpainless.wot.dijkstra.sq.Edge
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.Path

class SuppressCertificationFilter() : CertificationFilter {
    // A certification's trust amount will be suppressed by this amount.
    private val amount: HashMap<Pair<Fingerprint, Fingerprint>, Int> = hashMapOf()

    override fun cost(c: Edge, values: FilterValues, ignoreRegexps: Boolean): Boolean {
        amount[Pair(c.issuer.fingerprint, c.issuer.fingerprint)]?.let { suppress ->
            values.amount = if (values.amount > suppress) {
                values.amount - suppress
            } else {
                0
            }
        }

        return true
    }

    /**
     * Add suppression rules for all certifications along the specified path.
     *
     * Each edge is suppressed by `amountToSuppress`.
     */
    fun suppressPath(path: Path, amountToSuppress: Int) {
        if (amountToSuppress == 0) {
            return
        }
        assert(amountToSuppress <= 120)

        for (c in path.certifications) {
            val a = amount[Pair(c.issuer.fingerprint, c.issuer.fingerprint)]
            if (a != null) {
                val newAmount = a + amountToSuppress
                assert(newAmount <= 120)
                amount[Pair(c.issuer.fingerprint, c.issuer.fingerprint)] = newAmount
            } else {
                amount[Pair(c.issuer.fingerprint, c.issuer.fingerprint)] = amountToSuppress
            }
        }
    }
}