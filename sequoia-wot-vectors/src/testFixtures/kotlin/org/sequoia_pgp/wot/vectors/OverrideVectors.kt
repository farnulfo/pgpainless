// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

/**
 * alice
 *  | t0: 2/120, t1: 0/120
 *  v
 * bob
 *  |  120
 *  v
 * carol
 *
 * At t0, alice makes Bob a trusted introducer.  At t1, she issues
 * another certification, but only certifies bob.  Make sure that before
 * t1, alice can authenticate carol, but after t1 she can't.
 */
class OverrideVectors: ArtifactVectors {

    // TODO: Extract fingerprints and UIDs

    override val tempFilePrefix: String
        get() = "override"

    override fun getResourceName(): String {
        return "org/sequoia_pgp/wot/vectors/override.pgp"
    }
}