// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

/**
 * Four certificates that only make certifications (depth is always 0).
 *
 * ```
 * alice
 *  |  |\
 *  v   |
 * bob  |
 *  |   |
 *  v   |
 * carol|
 *  |   |
 *  v   /
 * dave
 * ```
 */
class CertificationNetworkVectors: ArtifactVectors {

    // TODO: Extract Fingerprints, UIDs and timestamps

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/certification-network.pgp"
    }

}