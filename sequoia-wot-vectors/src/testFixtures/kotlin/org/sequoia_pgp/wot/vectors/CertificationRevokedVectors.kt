// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * Alice may realize that she made a certification in error, e.g., she
 * realizes that she was tricked into certifying an incorrect identity by
 * Mallory.  Or, circumstances may change.  A person may leave an
 * organization, so the CA admin needs to invalidate the certification of
 * their organizational identity.
 *
 * Consider the following timeline:
 *
 *   t0: A, B, and C are created
 *   t1: A certifies B and B certifies C.
 *
 * ```
 *   A
 *   | 1/60
 *   B
 *   | 0/120
 *   C
 * ```
 *
 *   t2: A revokes their certification of B
 *
 *       A should now no longer be able to authenticate B or C.
 *
 *   t3: A recertifies B
 *
 * ```
 *   A
 *   | 1/120
 *   B
 *   | 0/120
 *   C
 * ```
 *
 *       A should be able to authenticate B and C.
 */
class CertificationRevokedVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("817C2BE18D9FF48FFE58FF39B699FC21AD92EFDC")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("4258ACF6C3C8FCE130D6EBAB0CC5158AEA25F24A")
    val bobUid = "<bob@example.org>"
    // Certified by: 817C2BE18D9FF48FFE58FF39B699FC21AD92EFDC
    // Certified by: 817C2BE18D9FF48FFE58FF39B699FC21AD92EFDC

    val carolFpr = Fingerprint("36766215FFD2FA000B0804BFF54577580DDC1741")
    val carolUid = "<carol@example.org>"
    // Certified by: 4258ACF6C3C8FCE130D6EBAB0CC5158AEA25F24A

    /**
     * A, B, C are created.
     */
    val t0 = parseReferenceTime("2020-01-01 00:00:00 UTC")

    /**
     * A certifies B, B certifies C.
     */
    val t1 = parseReferenceTime("2020-02-01 00:00:00 UTC")

    /**
     * A revokes their certification of B.
     * A should now no longer be able to authenticate B or C.
     */
    val t2 = parseReferenceTime("2020-03-01 00:00:00 UTC")

    /**
     * A re-certifies B.
     */
    val t3 = parseReferenceTime("2020-04-01 00:00:00 UTC")

    override val tempFilePrefix: String
        get() = "certification-revoked"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/certification-revoked.pgp"
    }
}