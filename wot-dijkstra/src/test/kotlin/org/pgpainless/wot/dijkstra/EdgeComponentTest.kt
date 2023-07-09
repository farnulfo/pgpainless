package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.Node
import org.pgpainless.wot.dijkstra.sq.EdgeComponent
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.RevocationState
import java.util.*
import kotlin.test.assertEquals

class EdgeComponentTest {

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
    fun `verify result of toString() on certification signature`() {
        val edgeComponent = EdgeComponent(alice, bob, "Bob <bob@example.org>", Date())
        assertEquals("A certifies binding: Bob <bob@example.org> <-> B [120]",
                edgeComponent.toString())
    }

    @Test
    fun `verify result of toString() on delegation signature`() {
        val delegation = EdgeComponent(alice, bob, null, Date())
        assertEquals("A certifies binding: null <-> B [120]",
                delegation.toString())
    }

    @Test
    fun `verify result of toString() on delegation signature with userId-less issuer`() {
        val delegation = EdgeComponent(charlie, bob, null, Date())
        assertEquals("C certifies binding: null <-> B [120]",
                delegation.toString())
    }
}