// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * In this test Alice has certified two different User IDs for Bob.
 * First, we check that at most one of those certifications is used.
 * Then we check that both are considered.  Because neither certification
 * is better than the other (one has a larger trust amount; the other has
 * more depth), different scenarios will result in different
 * certifications being selected.
 *
 *
 * Alice has certified two of Bob's User IDs.  One with a trust amount of
 * 50 and depth 2 and the other with a trust amount of 70 and depth 1.
 *
 * Using Alice as a root and authenticating Carol, we can get a trust
 * amount of 70.  Although Bob - Carol has a capacity of 120, we only use
 * one User ID per key.
 *
 * When authenticating Dave, we get a trust amount of 50.  This is
 * because the delegation with a trust amount of 70 does not have enough
 * depth to reach dave so we use the other certification.
 *
 * ```
 *                 alice
 *        50/2   /       \ 70/1
 *   bob@some.org - bob - bob@other.org
 *                   | 120/2
 *                 carol
 *                   | 120
 *                 dave
 * ```
 */
class MultipleUserIds1Vectors: ArtifactVectors {

    val aliceFpr = Fingerprint("2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("03182611B91B1E7E20B848E83DFC151ABFAD85D5")
    val bobUid = "<bob@other.org>"
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA
    val bob_some_orgUid = "<bob@some.org>"
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA

    val carolFpr = Fingerprint("9CA36907B46FE7B6B9EE9601E78064C12B6D7902")
    val carolUid = "<carol@example.org>"
    // Certified by: 03182611B91B1E7E20B848E83DFC151ABFAD85D5

    val daveFpr = Fingerprint("C1BC6794A6C6281B968A6A41ACE2055D610CEA03")
    val daveUid = "<dave@other.org>"
    // Certified by: 9CA36907B46FE7B6B9EE9601E78064C12B6D7902

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/multiple-userids-1.pgp"
    }
}