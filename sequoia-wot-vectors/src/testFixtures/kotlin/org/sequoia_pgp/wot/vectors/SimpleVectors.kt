// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * A straightforward certification chain.  Note: when A is the root, she
 * can authenticate D, but not E due to depth constraints.
 *
 * ```text
 *            o A
 *            |  2/100
 *            v
 *            o B
 *            |  1/100
 *            v
 *            o C                 o Frank
 *            |  1/100
 *            v
 *            o D
 *            |  1/100
 *            v
 *            o E
 * ```
 */
class SimpleVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D")
    val aliceUid = "<alice@example.org>";

    val bobFpr = Fingerprint("39A479816C934B9E0464F1F4BC1DCFDEADA4EE90")
    val bobUid = "<bob@example.org>"
    // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

    val carolFpr = Fingerprint("43530F91B450EDB269AA58821A1CF4DC7F500F04")
    val carolUid = "<carol@example.org>"
    // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

    val daveFpr = Fingerprint("329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281")
    val daveUid = "<dave@example.org>"
    // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

    val ellenFpr = Fingerprint("A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4")
    val ellenUid = "<ellen@example.org>"
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    val frankFpr = Fingerprint("2693237D2CED0BB68F118D78DC86A97CD2C819D9")
    val frankUid = "<frank@example.org>"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/simple.pgp"
    }
}