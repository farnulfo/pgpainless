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
            Fingerprint("0000000000000000000000000000000000000000"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Alice <alice@pgpainless.org>", RevocationState.notRevoked())))
    private val bob = CertSynopsis(
            Fingerprint("1111111111111111111111111111111111111111"),
            null,
            RevocationState.notRevoked(),
            mapOf(Pair("Bob <bob@example.org>", RevocationState.notRevoked())))
    private val charlie = CertSynopsis(
            Fingerprint("22222222222222222222222222222222222222222222"),
            null,
            RevocationState.notRevoked(),
            mapOf())

    @Test
    fun `verify result of toString() on certification`() {
        val certification = Certification(alice, "Bob <bob@example.org>", bob, Date())
        assertEquals("0000000000000000000000000000000000000000 (Alice <alice@pgpainless.org>) certifies [Bob <bob@example.org>] 1111111111111111111111111111111111111111",
                certification.toString())
    }

    @Test
    fun `verify result of toString() on delegation`() {
        val delegation = Certification(alice, null, bob, Date())
        assertEquals("0000000000000000000000000000000000000000 (Alice <alice@pgpainless.org>) delegates to 1111111111111111111111111111111111111111",
                delegation.toString())
    }

    @Test
    fun `verify result of toString() on delegation with userId-less issuer`() {
        val delegation = Certification(charlie, null, bob, Date())
        assertEquals("22222222222222222222222222222222222222222222 delegates to 1111111111111111111111111111111111111111",
                delegation.toString())
    }
}