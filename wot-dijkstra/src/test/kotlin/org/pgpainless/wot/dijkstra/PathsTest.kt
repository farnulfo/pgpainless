package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dijkstra.sq.*
import java.util.*
import kotlin.test.assertEquals

class PathsTest: NetworkDSL {

    private val alice = CertSynopsis("0000000000000000000000000000000000000000")
    private val bob = CertSynopsis("1111111111111111111111111111111111111111")

    private val alice_bob_1 = Certification(alice, bob, 140, Depth.unconstrained())
    private val alice_bob_2 = Certification(alice, bob, 160, Depth.limited(1))

    @Test
    fun `verify that an empty Paths object has an amount of zero`() {
        val empty = Paths()
        assertEquals(0, empty.amount)
    }

    @Test
    fun `verify that the amount of a Paths containing a single Path equals the Path's amount`() {
        val path = Path(alice).apply { append(alice_bob_1) }
        val single = Paths().apply { add(path, 140) }

        assertEquals(140, single.amount)
    }

    @Test
    fun `verify that the amounts of two Path objects sum up`() {
        val path1 = Path(alice).apply { append(alice_bob_1) }
        val path2 = Path(alice).apply { append(alice_bob_2) }
        val twoPaths = Paths().apply {
            add(path1, 140)
            add(path2, 160)
        }

        assertEquals(300, twoPaths.amount)
    }

    @Test
    fun `verify that a Path cannot be added if its amount is less than the method argument armound`() {
        val path = Path(alice).apply { append(alice_bob_1) }
        val paths = Paths()
        assertThrows<IllegalArgumentException> {
            paths.add(path, 250)
        }
    }
}