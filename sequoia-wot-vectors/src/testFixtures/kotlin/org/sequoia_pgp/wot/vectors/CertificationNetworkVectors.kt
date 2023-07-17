// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

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

    val aliceFpr = Fingerprint("B2B371214EF71AFD16E42C62D81360B4C0489225")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05")
    val bobUid = "<bob@example.org>"

    val carolFpr = Fingerprint("AB9EF1C89631519842ED559697557DD147D99C97")
    val carolUid = "<carol@example.org>"

    val daveFpr = Fingerprint("9A1AE937B5CB8BC46048AB63023CC01973ED9DF3")
    val daveUid = "<dave@example.org>"

    /**
     * A few minutes after the Network has been generated.
     */
    val t0 = parseReferenceTime("2023-01-19 12:00:00 UTC")

    override val tempFilePrefix: String
        get() = "certification-network"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/certification-network.pgp"
    }

}