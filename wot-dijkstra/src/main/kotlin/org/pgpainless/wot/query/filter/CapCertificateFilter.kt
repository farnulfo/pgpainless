// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query.filter

import org.pgpainless.wot.network.EdgeComponent
import org.pgpainless.wot.network.Fingerprint

class CapCertificateFilter() : CertificationFilter {

    // A certificate's trust amount will be limited to this amount.
    private val caps: HashMap<Fingerprint, Int> = hashMapOf()

    override fun cost(c: EdgeComponent, values: FilterValues, ignoreRegexps: Boolean): Boolean {
        caps[c.issuer.fingerprint]?.let {
            if (it < values.amount) {
                values.amount = it
            }
        }

        return true
    }

    /**
     * Add rules for the certificate.
     *
     * Any certifications issued by the certificate have their trust
     * amount limited to `cap`.  If a certificate is capped multiple
     * times, then the minimum cap is used.
     */
    fun cap(cert: Fingerprint, cap: Int) {
        val current = caps[cert]

        if ((current == null) || (current > cap)) {
            caps[cert] = cap
        }
    }
}
