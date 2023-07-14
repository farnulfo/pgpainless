// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * Consider the following timeline:
 *
 *   t0   A, B, C are created
 *
 *   t1   A certifies B - 2/60
 *        B certifies C - 1/60
 *
 *   t2   A certifies B (expires at t3) - 2/120
 *        B certifies C - 1/120
 *
 *   t3   A's certification of B at t2 expires.
 *
 * This results in:
 *
 * t1:
 *
 * ```text
 *         o A
 *    2/60 |
 *         v
 *         B
 *    1/60 |
 *         v
 *         o
 *         C
 * ```
 *
 * t2:
 *
 * ```text
 *          o A
 *    2/120 |
 *          v
 *          B
 *    1/120 |
 *          v
 *          o
 *          C
 * ```
 *
 * t3:
 *
 * ```text
 *         o A
 *    2/60 |
 *         v
 *         B
 *    1/60 |
 *         v
 *         o
 *         C
 * ```
 */
class CertificationLivenessVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("77C077250C26357E5E64A58A41426350B1D7F738")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("840891562819D3A108C4DA1BB31438DE34F8CF69")
    val bobUid = "<bob@example.org>"
    // Certified by: 77C077250C26357E5E64A58A41426350B1D7F738
    // Certified by: 77C077250C26357E5E64A58A41426350B1D7F738

    val carolFpr = Fingerprint("E8BB154D000C17AC87291D7271553C836973FE01")
    val carolUid = "<carol@example.org>"
    // Certified by: 840891562819D3A108C4DA1BB31438DE34F8CF69
    // Certified by: 840891562819D3A108C4DA1BB31438DE34F8CF69

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/certification-liveness.pgp"
    }
}