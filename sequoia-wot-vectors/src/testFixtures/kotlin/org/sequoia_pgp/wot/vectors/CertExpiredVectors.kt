// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * Check that an expired certificate can't be authenticated and can't be
 * used to authenticate other certificates.
 *
 *  t0: Create A, B, C
 *  t1: Create certifications (amount = 60)
 *  t2: B expires.
 *  t3: Create certifications (amount = 120)
 *
 * ```
 *   A
 *   | 1/60
 *   B
 *   | 1/60
 *   C
 * ```
 *
 * At t3, the new certifications are ignored, because they were created
 * after B expired.
 *
 * At t3, B can still be used as a trusted introducer for C, because the
 * initial certifications were created before it expired, but it is no
 * longer possible to authenticate B.
 */
class CertExpiredVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("1FA62523FB7C06E71EEFB82BB5159F3FC3EB3AC9")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("B166B31AE5F95600B3F7184FE74C6CE62821686F")
    val bobUid = "<bob@example.org>"
    // Certified by: 1FA62523FB7C06E71EEFB82BB5159F3FC3EB3AC9

    val carolFpr = Fingerprint("81CD118AC5BD9156DC113772626222D76ACDFFCF")
    val carolUid = "<carol@example.org>"
    // Certified by: B166B31AE5F95600B3F7184FE74C6CE62821686F

    /**
     * Create A, B, C.
     */
    val t0 = parseReferenceTime("2020-01-01 00:00:00 UTC")

    /**
     * Create certifications (amount = 60).
     */
    val t1 = parseReferenceTime("2020-02-01 00:00:00 UTC")

    /**
     * B expires.
     */
    val t2 = parseReferenceTime("2020-02-15 00:00:00 UTC")

    /**
     * Create certifications (amount = 120).
     */
    val t3 = parseReferenceTime("2020-04-01 00:00:00 UTC")
    override val tempFilePrefix: String
        get() = "cert-expired"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cert-expired.pgp"
    }
}