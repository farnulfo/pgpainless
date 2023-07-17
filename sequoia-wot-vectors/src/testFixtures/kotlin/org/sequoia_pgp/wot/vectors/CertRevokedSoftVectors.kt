// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * If a certificate is revoked, this impacts the validity of a
 * certification on it and the validity of a certification that it
 * makes.  There are 8 scenarios:
 *
 * 1./2.  t1 - A, B created
 *        t2 - A certifies B  OR  B certifies A
 *        t3 - A is soft revoked
 *        => certification is okay
 *
 * 3./4.  t1 - A, B created
 *        t2 - A is soft revoked
 *        t3 - A certifies B  OR  B certifies A
 *        => certification is bad
 *
 * 5./6.  t1 - A, B created
 *        t2 - A certifies B  OR  B certifies A
 *        t3 - A is hard revoked
 *        => certification is bad
 *
 * 7./8.  t1 - A, B created
 *        t2 - A is hard revoked
 *        t3 - A certifies B  OR  B certifies A
 *        => certification is bad
 *
 *
 * We want to consider both B as issuer of a certification and as the
 * target of a certification.  When B is an interior node (i.e., a
 * trusted introducer), we do both.  (Note: when B is the binding that we
 * are authenticating, then B also has to be valid at the reference
 * time!)  To check them separately, we can consider a path that is just
 * two nodes long where either the root or the target is revoked.  Since
 * roots are targets are treated specially, we also want to check when
 * the revoked node is an interior node.
 *
 * Thus, we need to also consider the
 * subgraph A - B and the subgraph B - D.
 *
 *
 * Consider the following timeline:
 *
 *   t0   A, B, C, D are created
 *
 *   t1   A certifies B - 2/120
 *        B certifies D - 1/60
 *        A certifies C - 2/30
 *        C certifies D - 1/120
 *
 * This results in:
 *
 * ```text
 *           o A
 *    2/90 /   \  2/30
 *        v     v
 *        B     C
 *    1/60 \   / 1/120
 *           v
 *           o
 *           D
 * ```
 *
 *   t2   B is soft revoked
 *
 * This does not change the network as the certification was made before
 * the soft revocation.  That is, we will be able to use B as a trust
 * introducers for certifications involving it prior to the revocation.
 * But, we won't be able to authenticate a binding involving B, because
 * it is revoked at the reference time:
 *
 * ```text
 *           o A
 *    2/90 /   \  2/30
 *        v     v
 *        B     C
 *    1/60 \   / 1/120
 *           v
 *           o
 *           D
 * ```
 *
 *   t3   A certifies B (amount = 120)
 *        B certifies D (amount = 120)
 *
 * Because these certifications are created after B was revoked, they
 * should be ignored.
 *
 * ```text
 *           o A
 *    2/90 /   \  2/30
 *        v     v
 *        B     C
 *    1/60 \   / 1/120
 *           v
 *           o
 *           D
 * ```
 */
class CertRevokedSoftVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("66037F98B444BBAFDFE98E871738DFAB86878262")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("4CD8737F76C2B897C4F058DBF28C47540FA2C3B3")
    val bobUid = "<bob@example.org>"
    // Certified by: 66037F98B444BBAFDFE98E871738DFAB86878262

    val carolFpr = Fingerprint("AB4E3F8EE8BBD3459754D75ACE570F9B8C7DC75D")
    val carolUid = "<carol@example.org>"
    // Certified by: 66037F98B444BBAFDFE98E871738DFAB86878262

    val daveFpr = Fingerprint("DF6A440ED9DE723B0EBC7F50E24FBB1B9FADC999")
    val daveUid = "<dave@example.org>"
    // Certified by: 4CD8737F76C2B897C4F058DBF28C47540FA2C3B3
    // Certified by: AB4E3F8EE8BBD3459754D75ACE570F9B8C7DC75D
    // Certified by: 4CD8737F76C2B897C4F058DBF28C47540FA2C3B3


    /**
     * A, B, C, D are generated.
     */
    val t0 = parseReferenceTime("2020-01-01 00:00:00 UTC")

    /**
     * A certifies B - 2/120.
     * B certifies D - 1/60.
     * A certifies C - 2/30.
     * C certifies D - 1/120.
     */
    val t1 = parseReferenceTime("2020-02-01 00:00:00 UTC")

    /**
     * B is soft revoked.
     */
    val t2 = parseReferenceTime("2020-03-01 00:00:00 UTC")

    /**
     * A certifies B (amount = 120).
     * B certifies D (amount = 120).
     */
    val t3 = parseReferenceTime("2020-04-01 00:00:00 UTC")

    override val tempFilePrefix: String
        get() = "cert-revoked-soft"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/cert-revoked-soft.pgp"
    }
}