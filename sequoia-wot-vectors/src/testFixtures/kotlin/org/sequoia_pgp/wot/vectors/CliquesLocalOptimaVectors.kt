// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

class CliquesLocalOptimaVectors: CliquesVectors() {

    /**
     * A few minutes after the network is fully generated.
     */
    val t0 = parseReferenceTime("2021-02-14 00:00:00 UTC")

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cliques-local-optima.pgp"
    }
}