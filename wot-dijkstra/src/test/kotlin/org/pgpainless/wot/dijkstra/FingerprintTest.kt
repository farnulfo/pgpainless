package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class FingerprintTest {

    @Test
    fun testConstructor() {
        val finger1 = Fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val finger2 = Fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        assert(finger1 == finger2)
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", finger1.fingerprint)
        assertEquals(finger1.hashCode(), finger2.hashCode())
    }

    @Test
    fun testEquals() {
        val finger1 = Fingerprint("0000000000000000000000000000000000000000")
        val finger2 = Fingerprint("1111111111111111111111111111111111111111")

        assertFalse { finger1.equals(null) }
        assert(finger1 == finger1)
        assert(finger1 != finger2)
        assertFalse { finger1.equals("2222222222222222222222222222222222222222") }
    }
}