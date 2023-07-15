// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.util.DateUtil
import org.pgpainless.wot.network.ReferenceTime

class ExampleTest {

    @Test
    fun test() {
        val vectors = BestViaRootVectors()
        val network = vectors.getNetworkAt(vectors.t1)
        println(network)
    }

    @Test
    fun exp() {
        val vectors = CertExpiredVectors()
        val keys = PGPainless.readKeyRing().publicKeyRingCollection(vectors.keyRingInputStream())
        val bob = keys.getPublicKeyRing(OpenPgpFingerprint.parse(vectors.bobFpr.toString()).keyId)
        val info = PGPainless.inspectKeyRing(bob, vectors.t1.timestamp)
        println(DateUtil.formatUTCDate(info.primaryKeyExpirationDate))
    }
}