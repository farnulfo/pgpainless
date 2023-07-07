package org.pgpainless.wot

import org.junit.jupiter.api.Test
import org.pgpainless.wot.testfixtures.AdHocVectors
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AdHocTest: PGPDSL {

    @Test
    fun test() {
        val vectors = AdHocVectors.BestViaRoot()
        val store = vectors.pgpCertificateStore
        val network = WebOfTrust(store).buildNetwork()
    }
}