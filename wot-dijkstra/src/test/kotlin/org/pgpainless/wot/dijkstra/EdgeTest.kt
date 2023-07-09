package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.Edge
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.RevocationState
import java.util.*
import kotlin.test.assertEquals

class EdgeTest {

    private val alice = Node(
            Fingerprint("A"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Alice <alice@pgpainless.org>", RevocationState.notRevoked())))
    private val bob = Node(
            Fingerprint("B"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Bob <bob@example.org>", RevocationState.notRevoked())))
    private val charlie = Node(
            Fingerprint("C"),
            null,
            RevocationState.notRevoked(),
            mapOf())

    @Test
    fun `verify result of toString() on certification`() {
        val edge = Edge(alice, bob, "Bob <bob@example.org>", Date())
        assertEquals("A certifies binding: Bob <bob@example.org> <-> B [120]",
                edge.toString())
    }

    @Test
    fun `verify result of toString() on delegation`() {
        val delegation = Edge(alice, bob, null, Date())
        assertEquals("A certifies binding: null <-> B [120]",
                delegation.toString())
    }

    @Test
    fun `verify result of toString() on delegation with userId-less issuer`() {
        val delegation = Edge(charlie, bob, null, Date())
        assertEquals("C certifies binding: null <-> B [120]",
                delegation.toString())
    }
}