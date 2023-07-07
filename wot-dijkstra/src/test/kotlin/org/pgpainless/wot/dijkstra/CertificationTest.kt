package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.CertSynopsis
import org.pgpainless.wot.dijkstra.sq.Certification
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.RevocationState
import java.util.*
import kotlin.test.assertEquals

class CertificationTest {

    private val alice = CertSynopsis(
            Fingerprint("A"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Alice <alice@pgpainless.org>", RevocationState.notRevoked())))
    private val bob = CertSynopsis(
            Fingerprint("B"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Bob <bob@example.org>", RevocationState.notRevoked())))
    private val charlie = CertSynopsis(
            Fingerprint("C"),
            null,
            RevocationState.notRevoked(),
            mapOf())

    @Test
    fun `verify result of toString() on certification`() {
        val certification = Certification(alice, "Bob <bob@example.org>", bob, Date())
        assertEquals("A certifies binding: Bob <bob@example.org> <-> B [120]",
                certification.toString())
    }

    @Test
    fun `verify result of toString() on delegation`() {
        val delegation = Certification(alice, null, bob, Date())
        assertEquals("A certifies binding: null <-> B [120]",
                delegation.toString())
    }

    @Test
    fun `verify result of toString() on delegation with userId-less issuer`() {
        val delegation = Certification(charlie, null, bob, Date())
        assertEquals("C certifies binding: null <-> B [120]",
                delegation.toString())
    }
}