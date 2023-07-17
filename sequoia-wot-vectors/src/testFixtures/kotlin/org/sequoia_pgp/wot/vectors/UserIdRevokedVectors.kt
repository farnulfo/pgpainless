// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * If a User ID is revoked, then that overrides any later positive
 * certification.
 *
 * We need to test three cases:
 *
 *   1. We are authenticating a root binding whose User ID was revoked in
 *      the past.
 *
 *   2. There is a valid path with length > 0 to a binding whose User ID
 *      is revoked.
 *
 *   3. There is a valid path to some binding.  The path uses a
 *      certification of a revoked User ID.
 *
 * In first two cases, it should not be possible to authenticate the
 * binding.  In the latter case, the revocation of the User ID should not
 * invalidate the delegation.
 *
 * To test this, we use the following network:
 *
 * ```
 *   A
 *   | 2/60 at t1; 2/90 at t3
 *   v
 *   B  <- B's User ID is revoked at t2
 *   | 1/60 at t1; 1/90 at t3
 *   v
 *   C
 * ```
 *
 * Using the above network, we can test all three scenarios.
 */
class UserIdRevokedVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("01672BB67E4B4047E5A4EC0A731CEA092C465FC8")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("EA479A77CD074458EAFE56B4861BF42FF490C581")
    val bobUid = "<bob@example.org>"
    // Certified by: 01672BB67E4B4047E5A4EC0A731CEA092C465FC8
    // Certified by: 01672BB67E4B4047E5A4EC0A731CEA092C465FC8

    val carolFpr = Fingerprint("212873BB9C4CC49F8E5A6FEA78BC5397470BA7F0")
    val carolUid = "<carol@example.org>"
    // Certified by: EA479A77CD074458EAFE56B4861BF42FF490C581
    // Certified by: EA479A77CD074458EAFE56B4861BF42FF490C581

    override val tempFilePrefix: String
        get() = "userid-revoked"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/userid-revoked.pgp"
    }
}