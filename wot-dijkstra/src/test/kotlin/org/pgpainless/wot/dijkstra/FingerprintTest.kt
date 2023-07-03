package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class FingerprintTest {

    @Test
    fun `verify that Fingerprint applies an uppercase() on the constructor argument`() {
        val fromLowerCase = Fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", fromLowerCase.fingerprint)
    }


    @Test
    fun `verify that objects constructed from the lower- and uppercase representation do equal`() {
        val finger1 = Fingerprint("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val finger2 = Fingerprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

        assert(finger1 == finger2)
        assertEquals(finger1.hashCode(), finger2.hashCode())
    }

    @Test
    fun `verify the proper function of the equals() method and == operator`() {
        val finger1 = Fingerprint("0000000000000000000000000000000000000000")
        val finger2 = Fingerprint("1111111111111111111111111111111111111111")

        assertFalse { finger1.equals(null) }
        assert(finger1 == finger1)
        assert(finger1 != finger2)
        assertFalse { finger1.equals("2222222222222222222222222222222222222222") }
    }
}