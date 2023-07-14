// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

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

    // TODO: Extract fingerprints and UIDs

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/gpg-trustroots.pgp"
    }
}