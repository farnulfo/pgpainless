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
    val aliceOtherOrguid = "<alice@other.org>"


    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/isolated-root.pgp"
    }
}