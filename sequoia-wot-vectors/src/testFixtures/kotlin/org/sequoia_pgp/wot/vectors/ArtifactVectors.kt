// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.pgpainless.PGPainless
import org.pgpainless.policy.Policy
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.WebOfTrust
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.ReferenceTime

interface ArtifactVectors {

    fun getResourceName(): String

    fun getNetworkAt(referenceTime: ReferenceTime, policy: Policy = PGPainless.getPolicy()): Network {
        return getNetworkAt(getResourceName(), referenceTime, policy)
    }

    private fun getNetworkAt(resourceName: String, referenceTime: ReferenceTime, policy: Policy): Network {
        val inputStream = ArtifactVectors::class.java.classLoader.getResourceAsStream(resourceName)!!
        val keyRing = PGPainless.readKeyRing().publicKeyRingCollection(inputStream)
        val store = KeyRingCertificateStore(keyRing)
        return WebOfTrust(store).buildNetwork(policy, referenceTime)
    }
}