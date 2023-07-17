// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * A - B - C should be valid.  The regex only applies to the target.
 *
 * ```
 *        alice@some.org
 *               | 100/7
 *        bob@some.org
 *               | 100/7/example.org
 *        carol@other.org
 *               | 100/7
 *        dave@their.org
 *               | 100/7
 *        ed@example.org
 * ```
 */
class Regex2Vectors: ArtifactVectors {

    val aliceFpr = Fingerprint("5C396C920399898461F17CB747FDBF3EB3453919")
    val aliceUid = "<alice@some.org>"

    val bobFpr = Fingerprint("584D195AD89CE0354D2CCBAEBCDD9EBC09692780")
    val bobUid = "<bob@some.org>"
    // Certified by: 5C396C920399898461F17CB747FDBF3EB3453919

    val carolFpr = Fingerprint("FC7A96D4810D0CF477031956AED58C644370C183")
    val carolUid = "<carol@other.org>"
    // Certified by: 584D195AD89CE0354D2CCBAEBCDD9EBC09692780

    val daveFpr = Fingerprint("58077E659732526C1B8BF9837EFC0EDE07B506A8")
    val daveUid = "<dave@their.org>"
    // Certified by: FC7A96D4810D0CF477031956AED58C644370C183

    val edFpr = Fingerprint("36089C49F18BF6FC6BCA35E3BB85877766C009E4")
    val edUid = "<ed@example.org>"
    // Certified by: 58077E659732526C1B8BF9837EFC0EDE07B506A8

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/regex-2.pgp"
    }
}