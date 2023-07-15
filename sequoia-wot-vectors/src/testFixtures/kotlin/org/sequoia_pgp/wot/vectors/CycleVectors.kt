// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * ```text
 *     Alice
 *      | 3,120
 *      |
 *      v   255,90
 *     Bob  -->   Carol
 *        ^       /
 *  255,120 \     v 255,60
 *          Dave
 *            |
 *            v  1,30
 *           Ed
 *            |
 *            v  0,120
 *          Frank
 * ```
 */
class CycleVectors: ArtifactVectors {
    val aliceFpr = Fingerprint("BFC5CA10FB55A4B790E2A1DBA5CFAB9A9E34E183")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("A637747DCF876A7F6C9149F74D47846E24A20C0B")
    val bobUid = "<bob@example.org>"
    // Certified by: 4458062DC7388909CF760E6823150D8E4408638A
    // Certified by: BFC5CA10FB55A4B790E2A1DBA5CFAB9A9E34E183

    val carolFpr = Fingerprint("394B04774FDAB0CDBF4D6FFD7930EA0FB549E303")
    val carolUid = "<carol@example.org>"
    // Certified by: A637747DCF876A7F6C9149F74D47846E24A20C0B

    val daveFpr = Fingerprint("4458062DC7388909CF760E6823150D8E4408638A")
    val daveUid = "<dave@example.org>"
    // Certified by: 394B04774FDAB0CDBF4D6FFD7930EA0FB549E303

    val edFpr = Fingerprint("78C3814EFD16E68F4F1AB4B874E30AE11FFCFB1B")
    val edUid = "<ed@example.org>"
    // Certified by: 4458062DC7388909CF760E6823150D8E4408638A

    val frankFpr = Fingerprint("A6219FF753AEAE2DE8A74E8487977DD568A08237")
    val frankUid = "<frank@example.org>"
    // Certified by: 78C3814EFD16E68F4F1AB4B874E30AE11FFCFB1B

    /**
     * A few minutes after the network has been generated.
     */
    val t0 = parseReferenceTime("2021-10-01 12:00:00 UTC")

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cycle.pgp"
    }
}