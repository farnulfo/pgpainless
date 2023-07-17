// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * alice makes bob a trusted introducer for the "example.org" domain.
 *
 * bob makes dave a trusted introducer for the "other.org" domain.
 *
 * This means that A - B - D - E is invalid, because ed@example.org is
 * out of scope of the B - D delegation (i.e., it does not match
 * other.org).
 *
 * ```
 *                    alice@some.org
 *                           | 100/3/example.org
 *                    bob@example.org
 *         150/0   /                  \ 100/3/other.org
 *        carol@example.org         dave@other.org
 *                              100/0  / \ 100/0
 *                       ed@example.org   frank@other.org
 * ```
 */
class Regex1Vectors: ArtifactVectors {

    val aliceFpr = Fingerprint("3AD1F297E4B150F75DBFC43476FB81BFE0665C3A")
    val aliceUid = "<alice@some.org>"

    val bobFpr = Fingerprint("20C812117FB2A3940EAE9160FEE6B4E47A096FD1")
    val bobUid = "<bob@example.org>"
    // Certified by: 3AD1F297E4B150F75DBFC43476FB81BFE0665C3A

    val carolFpr = Fingerprint("BC30978345D789CADECDE492F54B42E1625E1A1D")
    val carolUid = "<carol@example.org>"
    // Certified by: 20C812117FB2A3940EAE9160FEE6B4E47A096FD1

    val daveFpr = Fingerprint("319810FAD46CBE96DAD7F1F5B014902592999B21")
    val daveUid = "<dave@other.org>"
    // Certified by: 20C812117FB2A3940EAE9160FEE6B4E47A096FD1

    val edFpr = Fingerprint("23D7418EA0C6A42A54C32DBE8D4FE4911ED08467")
    val edUid = "<ed@example.org>"
    // Certified by: 319810FAD46CBE96DAD7F1F5B014902592999B21

    val frankFpr = Fingerprint("7FAE20D68EE87F74368AF275A0C40E741FC1C50F")
    val frankUid = "<frank@other.org>"
    // Certified by: 319810FAD46CBE96DAD7F1F5B014902592999B21

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/regex-1.pgp"
    }
}