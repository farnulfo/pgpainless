// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.filter

import org.pgpainless.wot.network.EdgeComponent
import org.pgpainless.wot.network.Fingerprint

/**
 * A filter that suppresses some capacity of an issuer.
 */
class SuppressIssuerFilter() : CertificationFilter {
    // A certification's trust amount will be suppressed by this amount.
    private val amount: HashMap<Fingerprint, Int> = hashMapOf()

    override fun cost(ec: EdgeComponent, values: FilterValues, ignoreRegexps: Boolean): Boolean {
        amount[ec.issuer.fingerprint]?.let { suppress ->
            values.amount = if (values.amount > suppress) {
                values.amount - suppress
            } else {
                0
            }
        }

        return true
    }

    /**
     * Add suppression rules for the issuer.
     *
     * Any certifications that the certificate makes are suppressed
     * (decreased) by that amount.
     */
    fun suppressIssuer(issuer: Fingerprint, amountToSuppress: Int) {
        if (amountToSuppress == 0) {
            return
        }
        assert(amountToSuppress <= 120)

        val a = amount[issuer]
        if (a != null) {
            val am = a + amountToSuppress
            assert(am <= 120)
            amount[issuer] = am
        } else {
            amount[issuer] = amountToSuppress
        }
    }
}