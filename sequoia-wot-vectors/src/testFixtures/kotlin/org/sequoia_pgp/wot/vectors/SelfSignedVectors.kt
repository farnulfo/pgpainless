// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * B tsigns <C, c1> and we want to authenticate c1.  This should work
 * when B is a root as C is considered a trusted introducer.  But it
 * should not work when A is considered a root a C can't introduce c2.
 *
 * ```
 *            A
 *     1/100  |
 *            B
 * 1/90    /
 *       c1 - C - c2
 *            |
 *        120 |
 *            D
 * ```
 */
class SelfSignedVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("838454E0D61D046300B408A908A4FDB4F368ECB9")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("7A7B5DE6C8F464CAB78BEFB9CE14BEE51D4DEC01")
    val bobUid = "<bob@example.org>"
    // Certified by: 838454E0D61D046300B408A908A4FDB4F368ECB9

    val carolFpr = Fingerprint("830230061426EE99A0455E6ADA869CF879A5630D")
    val carolUid = "<carol@example.org>"
    // Certified by: 7A7B5DE6C8F464CAB78BEFB9CE14BEE51D4DEC01
    val carolOtherOrgUid = "<carol@other.org>"

    val daveFpr = Fingerprint("51A5E15F87AC6ECAFBEA930FA5F30AF6EB6EF14A")
    val daveUid = "<dave@example.org>"
    // Certified by: 830230061426EE99A0455E6ADA869CF879A5630D

    override val tempFilePrefix: String
        get() = "self-signed"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/self-signed.pgp"
    }
}