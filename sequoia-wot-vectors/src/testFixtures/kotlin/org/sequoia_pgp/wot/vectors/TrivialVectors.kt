// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

class TrivialVectors: ArtifactVectors {

    // TODO: Extract fingerprints and UIDs

    override val tempFilePrefix: String
        get() = "trivial"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/trivial.pgp"
    }
}