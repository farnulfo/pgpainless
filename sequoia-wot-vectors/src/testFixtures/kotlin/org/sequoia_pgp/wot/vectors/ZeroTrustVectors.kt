// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * If the most recent certification has a trust amount of 0, then that
 * edge should not be considered.
 *
 * To test this, we use the following network:
 *
 * ```
 *   A
 *   | 1/120
 *   v
 *   B
 *   | 1/60 at t1; 1/0 at t2
 *   v
 *   C
 * ```
 *
 * At t1, there is a path from A to C.  At t2, there should be no path
 * (not even one with a trust amount of 0!).
 */
class ZeroTrustVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("931E51F99B89649783A1DFF265266E28246040C2")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("A1042B157AFA71F005208D645915549D8D21A97B")
    val bobUid = "<bob@example.org>"
    // Certified by: 931E51F99B89649783A1DFF265266E28246040C2
    // Certified by: 931E51F99B89649783A1DFF265266E28246040C2

    val carolFpr = Fingerprint("E06DB0539D99759681D7EC8508A267AE8FA838F4")
    val carolUid = "<carol@example.org>"
    // Certified by: A1042B157AFA71F005208D645915549D8D21A97B

    override val tempFilePrefix: String
        get() = "zero-trust"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/zero-trust.pgp"
    }
}