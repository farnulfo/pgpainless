// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * If a root is isolated, make sure we can still answer queries about it.
 *
 *   - t0: A is created
 *   - t1: A's User ID is revoked.
 */
class IsolatedRootVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("DCF3020AAB76ECC7F0E5AC0D375DCE1BEE264B87")
    val aliceUid = "<alice@example.org>"
    val aliceOtherOrgUid = "<alice@other.org>"

    /**
     * A is created.
     */
    val t0 = parseReferenceTime("2020-01-01 00:00:00 UTC")

    /**
     * A's UserID is revoked.
     */
    val t1 = parseReferenceTime("2020-02-01 00:00:00 UTC")

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/isolated-root.pgp"
    }
}