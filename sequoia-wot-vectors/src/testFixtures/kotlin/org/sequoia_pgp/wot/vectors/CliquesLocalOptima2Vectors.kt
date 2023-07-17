// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

class CliquesLocalOptima2Vectors: CliquesVectors() {

    override val tempFilePrefix: String
        get() = "cliques-local-optima-2"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cliques-local-optima-2.pgp"
    }
}