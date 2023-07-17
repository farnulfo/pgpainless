// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.wot.network.Fingerprint

/**
 * When doing backwards propagation, we find paths from all nodes to the
 * target.  Since we don't stop when we reach a root, the returned path
 * should still be optimal.  Consider:
 *
 * ```text
 * A --- 120/10 ---> B --- 120/10 ---> C --- 120/10 ---> Target
 *  \                                                      /
 *   `--- 50/10 ---> Y --- 50/10 ---> Z --- 50/10 --------'
 * ```
 *
 * When the root is B, then the path that we find for A should be `A -> B
 * -> C -> Target`, not `A -> Y -> Z -> Target`.
 *
 * Timeline:
 * - t0: keys are generated.
 * - t1: third-party certifications are issued.
 */
class BestViaRootVectors: ArtifactVectors {

    val aliceFpr = Fingerprint("B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB")
    val aliceUid = "<alice@example.org>"

    val bobFpr = Fingerprint("6A8B9EC7D0A1B297B5D4A7A1C048DFF96601D9BD")
    val bobUid = "<bob@example.org>"
    // Certified by: B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB

    val carolFpr = Fingerprint("77A6F7D4BEE0369F70B249579D2987669F792B35")
    val carolUid = "<carol@example.org>"
    // Certified by: 6A8B9EC7D0A1B297B5D4A7A1C048DFF96601D9BD

    val targetFpr = Fingerprint("2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0")
    val targetUid = "<target@example.org>"
    // Certified by: 77A6F7D4BEE0369F70B249579D2987669F792B35
    // Certified by: 56D44411F982758169E4681B402E8D5D9D7D6567

    val yellowFpr = Fingerprint("86CB4639D1FE096BA941D05822B8AF50198C49DD")
    val yellowUid = "<yellow@example.org>"
    // Certified by: B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB

    val zebraFpr = Fingerprint("56D44411F982758169E4681B402E8D5D9D7D6567")
    val zebraUid = "<zebra@example.org>"
    // Certified by: 86CB4639D1FE096BA941D05822B8AF50198C49DD

    /**
     * Create A, B, C, Y, Z, Target.
     */
    val t0 = parseReferenceTime("2021-09-27 12:51:50 UTC")

    /**
     * Create certifications.
     */
    val t1 = parseReferenceTime("2021-09-27 12:52:50 UTC")
    
    override val tempFilePrefix: String
        get() = "best-via-root"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/best-via-root.pgp"
    }
}