// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * This test is similar to [MultipleUserIds1Vectors], but it uses regular
 * expressions.  Specifically, Alice certifies two different User IDs for
 * Bob.  One of them with a depth of 1 and no regular expression, and the
 * other scoped to other.org, but with a higher trust amount and more
 * depth.
 *
 * ```
 *                 alice
 *                /     \
 *        50/1/'*' /       \ 70/255/@other.org
 *              /         \
 *   bob@some.org - bob - bob@other.org
 *                 /   \
 *         120/2  /     \  120
 *               /       \
 *             carol      frank@other.org
 *         120 /    \ 120
 * dave@other.org    ed
 * ```
 */
class MultipleUserIds2Vectors: ArtifactVectors {

    val alice_fpr = Fingerprint("F1C99C4019837703DD17C45440F8A0141DF278EA")
    val alice_uid = "<alice@example.org>"

    val bob_fpr = Fingerprint("5528B9E5DAFC519ED2E37F0377B332E4111456CB")
    val bob_uid = "<bob@other.org>"
    // Certified by: F1C99C4019837703DD17C45440F8A0141DF278EA
    val bob_some_org_uid = "<bob@some.org>"
    // Certified by: F1C99C4019837703DD17C45440F8A0141DF278EA

    val carol_fpr = Fingerprint("6F8291428420AB53576BAB4BEFF6477D3E348D71")
    val carol_uid = "<carol@example.org>"
    // Certified by: 5528B9E5DAFC519ED2E37F0377B332E4111456CB

    val dave_fpr = Fingerprint("62C57D90DAD253DEA01D5A86C7382FD6285C18F0")
    val dave_uid = "<dave@other.org>"
    // Certified by: 6F8291428420AB53576BAB4BEFF6477D3E348D71

    val ed_fpr = Fingerprint("0E974D0ACBA0C4D8F51D7CF68F048FF83B173504")
    val ed_uid = "<ed@example.org>"
    // Certified by: 6F8291428420AB53576BAB4BEFF6477D3E348D71

    val frank_fpr = Fingerprint("5BEE3D41F85B2FCBC300DE4E18CB2BDA65465F03")
    val frank_uid = "<frank@other.org>"
    // Certified by: 5528B9E5DAFC519ED2E37F0377B332E4111456CB

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/multiple-userids-2.pgp"
    }
}