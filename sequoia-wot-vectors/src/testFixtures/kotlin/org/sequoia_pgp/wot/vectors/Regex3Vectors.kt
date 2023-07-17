// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * Here we have multiple regular expressions on a single delegation.
 *
 *
 * ```
 *                            alice@some.org
 *                               | 100/3/example.org|other.org
 *                     _     bob@example.org                  _
 *           100/0   /           | 100/3/their.org|other.org    \
 *     carol@example.org  _   dave@other.org   _                 henry@their.org
 *                100/0  /       | 100/0        \ 100/0
 *         ed@example.org     frank@other.org     george@their.org
 * ```
 */
class Regex3Vectors: ArtifactVectors {

    val aliceFpr = Fingerprint("D8CFEBBA006E2ED57CF45CC413F0BAE09D94FE4E")
    val aliceUid = "<alice@some.org>"

    val bobFpr = Fingerprint("A75DC1A1EDA5282F3A7381B51824E46BBCC801F0")
    val bobUid = "<bob@example.org>"
    // Certified by: D8CFEBBA006E2ED57CF45CC413F0BAE09D94FE4E

    val carolFpr = Fingerprint("4BCD4325BDACA452F0301227A30CB4BCC329E769")
    val carolUid = "<carol@example.org>"
    // Certified by: A75DC1A1EDA5282F3A7381B51824E46BBCC801F0

    val daveFpr = Fingerprint("2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380")
    val daveUid = "<dave@other.org>"
    // Certified by: A75DC1A1EDA5282F3A7381B51824E46BBCC801F0

    val edFpr = Fingerprint("F645D081F480BE26C7D2C84D941B3E2CE53FAF16")
    val edUid = "<ed@example.org>"
    // Certified by: 2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380

    val frankFpr = Fingerprint("AFAB11F1A37FD20C85CF8093F4941D1A0EC5749F")
    val frankUid = "<frank@other.org>"
    // Certified by: 2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380

    val georgeFpr = Fingerprint("D01C8752D9BA9F3F5F06B21F394E911938D6DB0A")
    val georgeUid = "<george@their.org>"
    // Certified by: 2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380

    val henryFpr = Fingerprint("B99A8696FD820192CEEE285D3A253E49F1D97109")
    val henryUid = "<henry@their.org>"
    // Certified by: A75DC1A1EDA5282F3A7381B51824E46BBCC801F0

    override val tempFilePrefix: String
        get() = "regex-3"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/regex-3.pgp"
    }
}