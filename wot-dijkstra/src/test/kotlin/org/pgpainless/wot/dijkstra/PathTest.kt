package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dijkstra.sq.*
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PathTest: NetworkDSL {

    private val root = CertSynopsis("aabbccddeeAABBCCDDEEaabbccddeeAABBCCDDEE")
    private val alice = CertSynopsis("0000000000000000000000000000000000000000")
    private val bob = CertSynopsis("1111111111111111111111111111111111111111")

    // Root -(255, 255)-> Alice
    private val root_alice__fully_trusted = Certification(root, alice, 255, Depth.unconstrained())
    // Root -(60,0)-> Alice
    private val root_alice__marginally_trusted = Certification(root, alice, 60, Depth.limited(0))
    // Alice -(255,255)-> Root
    private val alice_root = Certification(alice, root, 255, Depth.unconstrained())
    // Alice -(120, 1)-> Bob
    private val alice_bob = Certification(alice, bob)
    // Root -> Root
    private val root_root = Certification(root, root, 120, Depth.limited(1))

    @Test
    fun `verify that an empty Path is properly initialized`() {
        val empty = Path(root)
        assertEquals(root, empty.target)
        assertEquals(listOf(root), empty.certificates)
        assertEquals(1, empty.length)
        assertEquals(120, empty.amount)
        assertTrue { empty.certifications.isEmpty() }
    }

    @Test
    fun `verify that append()ing multiple Certifications properly changes the trust amount of the Path`() {
        val path = Path(root)
        assertEquals(1, path.length)
        assertEquals(120, path.amount) // default amount of an empty path

        path.append(root_alice__fully_trusted)
        assertEquals(listOf(root_alice__fully_trusted), path.certifications)
        assertEquals(listOf(root, alice), path.certificates)
        assertEquals(alice, path.target)
        assertEquals(2, path.length)
        assertEquals(255, path.amount) // single certification -> path has its amount

        path.append(alice_bob)
        assertEquals(listOf(root_alice__fully_trusted, alice_bob), path.certifications)
        assertEquals(listOf(root, alice, bob), path.certificates)
        assertEquals(bob, path.target)
        assertEquals(3, path.length)
        assertEquals(120, path.amount) // second certification has less amount, so amount is capped to its value
    }

    @Test
    fun `verify that append()ing a Certification whose issuer mismatches the target of the Path fails`() {
        val path = Path(root)
        assertEquals(listOf(root), path.certificates)
        assertEquals(1, path.length)
        assertThrows<IllegalArgumentException> { path.append(alice_bob) }
    }

    @Test
    fun `verify that append()ing a Certification fails if it exceeds the Path's depth`() {
        val path = Path(root)
        path.append(root_alice__marginally_trusted)
        assertEquals(60, path.amount)

        assertThrows<IllegalArgumentException> {
            path.append(alice_bob)
            // not enough depth
        }
    }

    @Test
    fun `verify that append()ing a Certification fails of the result would contain cycles`() {
        val path = Path(root)
        path.append(root_alice__fully_trusted)
        assertThrows<IllegalArgumentException> {
            path.append(alice_root)
            // cyclic path
        }
    }

    @Test
    fun `verify that a Path cannot point to its own root`() {
        val path = Path(root)
        assertThrows<IllegalArgumentException> { path.append(root_root) }
    }
}