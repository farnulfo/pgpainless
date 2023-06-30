package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dijkstra.sq.*
import java.util.*
import kotlin.test.assertEquals

class PathsTest {

    private val alice = CertSynopsis(
            Fingerprint("0000000000000000000000000000000000000000"),
            null,
            RevocationState.notRevoked(),
            mapOf())
    private val bob = CertSynopsis(
            Fingerprint("1111111111111111111111111111111111111111"),
            null,
            RevocationState.notRevoked(),
            mapOf())

    private val alice_bob_1 = Certification(alice, bob, 140, Depth.unconstrained())
    private val alice_bob_2 = Certification(alice, bob, 160, Depth.limited(1))

    @Test
    fun emptyPathsTest() {
        val empty = Paths()
        assertEquals(0, empty.amount)
    }

    @Test
    fun singlePathTest() {
        val path = Path(alice).apply { append(alice_bob_1) }
        val single = Paths().apply { add(path, 140) }

        assertEquals(140, single.amount)
    }

    @Test
    fun twoPathsTest() {
        val path1 = Path(alice).apply { append(alice_bob_1) }
        val path2 = Path(alice).apply { append(alice_bob_2) }
        val twoPaths = Paths().apply {
            add(path1, 140)
            add(path2, 160)
        }

        assertEquals(300, twoPaths.amount)
    }

    @Test
    fun notEnoughAmountTest() {
        val path = Path(alice).apply { append(alice_bob_1) }
        val paths = Paths()
        assertThrows<IllegalArgumentException> {
            paths.add(path, 250)
        }
    }

    fun Certification(issuer: CertSynopsis, target: CertSynopsis, amount: Int, depth: Depth): Certification =
            Certification(issuer, target, null, Date(), null, true, amount, depth, RegexSet.wildcard())
}