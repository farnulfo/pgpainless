// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * Creates 4 10 element cliques.  To authenticate the target, the path
 * finder must find it's way through them.  If the algorithm is NP
 * complete, then it will take a long time to do this.
 *
 * The cliques-local-optima variant includes an additional certification
 * from the target to a-0, which will trip up simple heuristics.
 *
 * For added fun, we also add a local optimum in the -local-optimum
 * variant:
 *
 *   - root -- 200/30 --> a1
 *   - root -- 255/30 --> b0
 *
 * And a second local optimum in the -local-optimum-2 variant:
 *
 *   - b1 -- 255/30 --> c1
 *
 * ```
 *           root ----------------------+-.
 *  100/120   |                         | |
 *            |                  200/30 | | 255/30
 *            v                         | |
 *            a0  a9  a8  a7  a6        | |
 *              \  |   |  /  /          | |
 *  100/120         Clique              | |
 *              /  |   |  \  \          | |
 *            a1 _a2  a3  a4  a5        | |
 *            | |\.---------------------' |
 *  100/120   |   .-----------------------'
 *            v |/_
 *            b0  b9  b8  b7  b6
 *              \  |   |  /  /
 *  100/120         Clique
 *              /  |   |  \  \
 *            b1  b2  b3  b4  b5
 *  100/120   | \---------------------.
 *            v                       |
 *            c0  c9  c8  c7  c6      |
 *              \  |   |  /  /        | 255/30
 *  100/120         Clique            |
 *              /  |   |  \  \        |
 *            c1  c2  c3  c4  c5      |
 *  100/120   | \---------------------'
 *            v
 *            d0  d9  d8  d7  d6
 *              \  |   |  /  /
 *  100/120         Clique
 *              /  |   |  \  \
 *            d1  d2  d3  d4  d5
 *  100/120   |
 *            v
 *            e0
 *  100/120   |
 *            v
 *            f0
 *  100/120   |
 *            v
 *          target
 * ```
 */
open class CliquesVectors: ArtifactVectors {

    val rootFpr = Fingerprint("D2B0C3835C01B0C120BC540DA4AA8F880BA512B5")
    val rootUid = "<root@example.org>"

    val a0Fpr = Fingerprint("363082E9EEB22E50AD303D8B1BFE9BA3F4ABD40E")
    val a0Uid = "<a-0@example.org>"

    val a1Fpr = Fingerprint("7974C04E8D5B540D23CD4E62DDFA779D91C69894")
    val a1Uid = "<a-1@example.org>"

    val b0Fpr = Fingerprint("25D8EAAB894705BB64D4A6A89649EF81AEFE5162")
    val b0Uid = "<b-0@example.org>"

    val b1Fpr = Fingerprint("46D2F5CED9BD3D63A11DDFEE1BA019506BE67FBB")
    val b1Uid = "<b-1@example.org>"

    val c0Fpr = Fingerprint("A0CD87582C21743C0E30637F7FADB1C3FEFBFE59")
    val c0Uid = "<c-0@example.org>"

    val c1Fpr = Fingerprint("5277C14F9D37A0F4D615DD9CCDCC1AC8464C8FE5")
    val c1Uid = "<c-1@example.org>"

    val d0Fpr = Fingerprint("C24CC09102D22E38E8393C55166982561E140C03")
    val d0Uid = "<d-0@example.org>"

    val d1Fpr = Fingerprint("7A80DB5330B7D900D5BD1F82EAD72FF7914078B2")
    val d1Uid = "<d-1@example.org>"

    val e0Fpr = Fingerprint("D1E9F85CEF6271699FBDE5AB26EFE0E035AC522E")
    val e0Uid = "<e-0@example.org>"

    val f0Fpr = Fingerprint("C0FFAEDEF0928B181265775A222B480EB43E0AFF")
    val f0Uid = "<f-0@example.org>"

    val targetFpr = Fingerprint("CE22ECD282F219AA99598BA3B58A7DA61CA97F55")
    val targetUid = "<target@example.org>"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cliques.pgp"
    }
}