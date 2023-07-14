// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * The best way from A to B, G and H is via C-D-E-F.  The best way from A
 * to I is via B!  (A has two local optima.)
 *
 * J complicates things a bit when doing a backwards propagation.
 *
 * ```
 *         A
 *         | \  6,120
 *         |  C
 *         |  |  5,120
 *         |  D
 * 100,60  |  |  4,120      5,100
 *         |  E <----------------- J
 *         |  | 3,120              |
 *         |  F                    |
 *         v /  2,120              | 1,100
 *         B                       |
 *  2,120  |                       |
 *         v                       |
 *         G <---------------------'
 *  1,120  |
 *         v
 *         H
 *  0,120  |
 *         v
 *         I
 * ```
 *
 */
class RoundaboutVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("41E9B069C96EB6D47525294B10BBBD00912BEA02")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("2E90AEE966DF28CB916439B20397E086E705AC1A")
    val bobUid = "<bob@example.org>"
    // Certified by: 3267D46247D26101B3E5014CDF4F9BA5831D91DA
    // Certified by: 41E9B069C96EB6D47525294B10BBBD00912BEA02

    val carolFpr = Fingerprint("92DDE8747C8E6ED09D41A4E1330D1190E858754C")
    val carolUid = "<carol@example.org>"
    // Certified by: 41E9B069C96EB6D47525294B10BBBD00912BEA02

    val daveFpr = Fingerprint("D4515E6619084ED8142DF8589059E3846A025611")
    val daveUid = "<dave@example.org>"
    // Certified by: 92DDE8747C8E6ED09D41A4E1330D1190E858754C

    val elmarFpr = Fingerprint("E553C11DCFA777F3205E5090F5EE59C2795CDBA2")
    val elmarUid = "<elmar@example.org>"
    // Certified by: AE40578962411356F9609CAA9C2447E61FFDBB15
    // Certified by: D4515E6619084ED8142DF8589059E3846A025611

    val frankFpr = Fingerprint("3267D46247D26101B3E5014CDF4F9BA5831D91DA")
    val frankUid = "<frank@example.org>"
    // Certified by: E553C11DCFA777F3205E5090F5EE59C2795CDBA2

    val georgeFpr = Fingerprint("CCD5DB27BD7C4F8E2010083605EF17E8A93EB652")
    val georgeUid = "<george@example.org>"
    // Certified by: AE40578962411356F9609CAA9C2447E61FFDBB15
    // Certified by: 2E90AEE966DF28CB916439B20397E086E705AC1A

    val henryFpr = Fingerprint("7F62EF97091AE1FCB4E1C67EC8D9E94C4731529B")
    val henryUid = "<henry@example.org>"
    // Certified by: CCD5DB27BD7C4F8E2010083605EF17E8A93EB652

    val isaacFpr = Fingerprint("32FD4D68B3227334CD0583E9FA0721F49D2F395D")
    val isaacUid = "<isaac@example.org>"
    // Certified by: 7F62EF97091AE1FCB4E1C67EC8D9E94C4731529B

    val jennyFpr = Fingerprint("AE40578962411356F9609CAA9C2447E61FFDBB15")
    val jennyUid = "<jenny@example.org>"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/roundabout.pgp"
    }
}