// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * ```
 *                a
 *       40/2  /     \ 30/3           \ 10/255
 * bob@some.org - b - bob@other.org   bob@third.org
 *         20/1 /   \ 120/2
 *             c     d
 *             |     | 120/1
 *         120 |     e
 *              \   / 120
 *                f
 * ```
 *
 * The first time back propagation is run, the algorithm will find the
 * path a - b - c - f (b prefers c - f to d - e - f, because the former
 * is shorter).  The second time it is run, it will find a - b - d - e -
 * f.  The path's trust amount will be 10, because we suppress 20 between
 * a and b, and we can't use the bob@some.org certification as it doesn't
 * not have enough depth.
 */
class MultipleUserIds3Vectors: ArtifactVectors {

    val alice_fpr = Fingerprint("DA3CFC60BD4B8835702A66782C7A431946C12DF7")
    val alice_uid = "<alice@example.org>"

    val bob_fpr = Fingerprint("28C108707090FCDFF630D1E141FB02F0E397D55E")
    val bob_uid = "<bob@other.org>"
    // Certified by: DA3CFC60BD4B8835702A66782C7A431946C12DF7
    val bob_some_org_uid = "<bob@some.org>"
    // Certified by: DA3CFC60BD4B8835702A66782C7A431946C12DF7
    val bob_third_org_uid = "<bob@third.org>"

    val carol_fpr = Fingerprint("9FB1D2F41AB5C478378E728C8DD5A5A434EEAAB8")
    val carol_uid = "<carol@example.org>"
    // Certified by: 28C108707090FCDFF630D1E141FB02F0E397D55E

    val dave_fpr = Fingerprint("0C131F8959F45D08B6136FDAAD2E16A26F73D48E")
    val dave_uid = "<dave@example.org>"
    // Certified by: 28C108707090FCDFF630D1E141FB02F0E397D55E

    val ed_fpr = Fingerprint("296935FAE420CCCF3AEDCEC9232BFF0AE9A7E5DB")
    val ed_uid = "<ed@example.org>"
    // Certified by: 0C131F8959F45D08B6136FDAAD2E16A26F73D48E

    val frank_fpr = Fingerprint("A72AA1B7D9D8CB04D988F1520A404E37A7766608")
    val frank_uid = "<frank@example.org>"
    // Certified by: 9FB1D2F41AB5C478378E728C8DD5A5A434EEAAB8
    // Certified by: 296935FAE420CCCF3AEDCEC9232BFF0AE9A7E5DB

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/multiple-userids-3.pgp"
    }
}