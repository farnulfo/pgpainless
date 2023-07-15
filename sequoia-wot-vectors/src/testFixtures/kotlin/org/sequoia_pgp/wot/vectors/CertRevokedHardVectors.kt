// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * The same as [CertRevokedSoftVectors], but using hard revocations.
 */
class CertRevokedHardVectors: ArtifactVectors {
    val aliceFpr = Fingerprint("219AAB661C8AAF4526DBC31AA751A7A0532863BA")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("90E02BFB03FAA04714D1D3D87543157EF3B12BE9")
    val bobUid = "<bob@example.org>"
    // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA
    // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA

    val carolFpr = Fingerprint("BF680710128E6BCCB2268154569F5F6BFB95C544")
    val carolUid = "<carol@example.org>"
    // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA

    val daveFpr = Fingerprint("46945292F8F643F0573AF71183F9C1A4759A16D6")
    val daveUid = "<dave@example.org>"
    // Certified by: 90E02BFB03FAA04714D1D3D87543157EF3B12BE9
    // Certified by: BF680710128E6BCCB2268154569F5F6BFB95C544
    // Certified by: 90E02BFB03FAA04714D1D3D87543157EF3B12BE9

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cert-revoked-hard.pgp"
    }
}