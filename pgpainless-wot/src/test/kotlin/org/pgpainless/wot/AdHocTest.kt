package org.pgpainless.wot

import org.junit.jupiter.api.Test
import org.pgpainless.wot.testfixtures.AdHocVectors

class AdHocTest {

    @Test
    fun test() {
        val store = AdHocVectors.BestViaRoot().pgpCertificateStore
        val wot = WebOfTrust(store).also { it.initialize() }
        val network = wot.network
    }
}