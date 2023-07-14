// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

/**
 * Certifications made prior to 1673363202 are made with SHA-1.
 */
class Sha1Vectors: ArtifactVectors {

    // TODO: Extract fingerprints and UIDs

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/sha1.pgp"
    }
}