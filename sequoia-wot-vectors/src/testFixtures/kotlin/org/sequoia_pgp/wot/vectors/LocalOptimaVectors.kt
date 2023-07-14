// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * The best path from A to F is: A - B - C - E - F (amount: 100).  Back
 * propagation will choose: A - B - F (amount: 75), because it is
 * shorter.  Make sure we don't choose A - B - D - E - F.
 *
 * For F, A - B - C - E is optimal (amount: 100).  Back propagation will
 * choose it, because at B, C - E and D - E have the same depth, but C -
 * E has a larger trust amount.
 *
 * For G, A - B - C - E - G and A - B - D - E - G are equally good.  But,
 * we will select the latter, because when we have a choice (at E), we
 * prefer more residual depth.
 *
 * For H, A - B - C - E - H is better.
 *
 * Notation: amount/depth
 *
 * ```text
 *              A
 *              | 120/150
 *              v
 *              B -------------,
 *   100/50  /  |              |
 *          v   v 50/100       |
 *          C   D              |  75/200
 *   100/50  \  | 50/100       |
 *           _\|v              |
 *              o E --------   v
 *            /   \         `->F
 *     120/0 /     \ 30/0   120/100
 *          v       v
 *          H       G
 * ```
 */
class LocalOptimaVectors: ArtifactVectors {
    val aliceFpr = Fingerprint("EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F")
    val bobUid = "<bob@example.org>"
    // Certified by: EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8
    // Certified by: EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8

    val carolFpr = Fingerprint("E9DF94E389F529F8EF6AA223F6CC1F8544C0874D")
    val carolUid = "<carol@example.org>"
    // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F
    // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

    val daveFpr = Fingerprint("C2F822F17B68E946853A2DCFF55541D89F27F88B")
    val daveUid = "<dave@example.org>"
    // Certified by: E9DF94E389F529F8EF6AA223F6CC1F8544C0874D
    // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

    val ellenFpr = Fingerprint("70507A9058A57FEAE18CC3CE6A398AC9051D9CA8")
    val ellenUid = "<ellen@example.org>"
    // Certified by: C2F822F17B68E946853A2DCFF55541D89F27F88B
    // Certified by: C2F822F17B68E946853A2DCFF55541D89F27F88B
    // Certified by: E9DF94E389F529F8EF6AA223F6CC1F8544C0874D

    val francisFpr = Fingerprint("D8DDA78A2297CA3C35B9377577E8B54B9350C082")
    val francisUid = "<francis@example.org>"
    // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8
    // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

    val georginaFpr = Fingerprint("C5D1B22FEC75911A04E1A5DC75B66B994E70ADE2")
    val georginaUid = "<georgina@example.org>"
    // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8

    val henryFpr = Fingerprint("F260739E3F755389EFC2FEE67F58AACB661D5120")
    val henryUid = "<henry@example.org>"
    // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/local-optima.pgp"
    }
}