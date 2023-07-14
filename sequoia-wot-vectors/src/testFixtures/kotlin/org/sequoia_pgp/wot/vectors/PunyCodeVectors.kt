// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

/**
 * This is a simple network where a User ID contains an email address
 * that would be normalized by puny code.
 *
 *
 * ```text
 *            o alice
 *            |  2/100
 *            v
 *            o hANS@bücher.tld
 *            |  1/100
 *            v
 *            o carol
 * ```
 */
class PunyCodeVectors: ArtifactVectors {

    // TODO: Extract fingerprints and UIDs

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/puny-code.pgp"
    }
}