// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * How gpg interprets ownertrust is a bit complicated.  For a certificate
 * that is marked as "fully trusted" or "partially trusted" to be
 * considered a trust root, it also has to be reachable from an
 * ultimately trusted trust root.  Further, it is permissible for that to
 * happen via fully trusted or marginally trusted trust roots.  Consider:
 *
 *
 * ```
 *              root
 * 0/120    /    |     \
 *         a1    a2    a3
 * 0/120    \    |     /
 *               d
 *               |
 *             target
 * ```
 *
 * Clearly, d cannot be authenticated from the root.  But if a1, a2, and
 * a3 are partially trusted trust roots, then it can be.  This means that
 * sq-wot has to iterate when adding gpg trust roots.
 */
class GpgTrustrootsVectors: ArtifactVectors {

    val rootFpr = Fingerprint("D8330354E99DB503729A68D4AAE7E9EC2129CEC3")
    val rootUid = "<root@example.org>"

    val a1Fpr = Fingerprint("80666EDD21A008D467243E47444D4C0F515D269A")
    val a1Uid = "<a1@example.org>"

    val a2Fpr = Fingerprint("A6D2F50B1C9544A717B7625395FD89DA7093B735")
    val a2Uid = "<a2@example.org>"

    val a3Fpr = Fingerprint("AFDD8AECD999F5CDC7027B23EECC4F0EA03A5F35")
    val a3Uid = "<a3@example.org>"

    val dFpr = Fingerprint("BB0333A98A05430FF6A784A706D474BF36A3D4F9")
    val dUid = "<d@example.org>"

    val targetFpr = Fingerprint("30A185EA9319FF1D0BCBDBFCF2CD31DCC3DCAA02")
    val targetUid = "<target@example.org>"

    /**
     * Certificates are generated.
     */
    val t0 = parseReferenceTime("2020-01-01 00:00:00 UTC")

    /**
     * Certifications are made.
     */
    val t1 = parseReferenceTime("2020-02-01 00:00:00 UTC")

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/gpg-trustroots.pgp"
    }
}