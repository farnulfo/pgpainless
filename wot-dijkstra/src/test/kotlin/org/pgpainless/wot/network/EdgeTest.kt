// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EdgeTest {

    private val alice = Node(Fingerprint("A"), null, RevocationState.notRevoked(), mapOf())
    private val bob = Node(Fingerprint("B"), null, RevocationState.notRevoked(), mapOf())
    private val charlie = Node(Fingerprint("C"), null, RevocationState.notRevoked(), mapOf())

    private val aliceSignsBob = EdgeComponent(alice, bob, null, Date())
    private val aliceSignsBobUserId = EdgeComponent(alice, bob, "Bob <bob@example.org>", Date())
    private val aliceSignsCharlie = EdgeComponent(alice, charlie, null, Date())
    private val charlieSignsBob = EdgeComponent(charlie, bob, null, Date())

    @Test
    fun `verify that properties of an empty edge are also empty`() {
        val empty = Edge.empty(alice, bob)
        assert(empty.components.isEmpty())
        assertEquals(alice, empty.issuer)
        assertEquals(bob, empty.target)
    }

    @Test
    fun `verify that add()ing edge components works if issuer and target match that of the edge`() {
        val set = Edge.empty(alice, bob)

        set.add(aliceSignsBob)
        assertTrue {
            set.components.values.any {
                it.contains(aliceSignsBob)
            }
        }
        set.add(aliceSignsBobUserId)
        assertTrue {
            set.components["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId)
        }
    }

    @Test
    fun `verify that add()ing another component fails if the issuer mismatches`() {
        val set = Edge.empty(alice, bob)
        assertThrows<IllegalArgumentException> { set.add(charlieSignsBob) }
    }

    @Test
    fun `verify that add()ing another component fails if the target mismatches`() {
        val set = Edge.empty(alice, bob)
        assertThrows<IllegalArgumentException> { set.add(aliceSignsCharlie) }
    }

    @Test
    fun `verify that merge()ing another edge works if issuer and target match that of the edge`() {
        val set = Edge.fromCertification(aliceSignsBob)
        val others = Edge.fromCertification(aliceSignsBobUserId)

        set.merge(others)
        assertEquals(2, set.components.size)
        assertTrue { set.components[null]!!.contains(aliceSignsBob) }
        assertTrue { set.components["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId) }
    }

    @Test
    fun `verify that merge()ing another edge with mismatched issuer fails`() {
        val set = Edge.fromCertification(aliceSignsBob)
        val issuerMismatch = Edge.fromCertification(charlieSignsBob)

        assertThrows<IllegalArgumentException> { set.merge(issuerMismatch) }
    }

    @Test
    fun `verify that merge()ing another edge with mismatched target fails`() {
        val set = Edge.fromCertification(aliceSignsBob)
        val targetMismatch = Edge.fromCertification(aliceSignsCharlie)

        assertThrows<IllegalArgumentException> { set.merge(targetMismatch) }
    }

    @Test
    fun `verify that merge()ing an edge with itself is idempotent`() {
        val set = Edge.fromCertification(aliceSignsBob)
        assertEquals(1, set.components.size)
        set.merge(set)
        assertEquals(1, set.components.size)
    }

    @Test
    fun `verify that toString() of an empty edge is the empty string`() {
        val empty = Edge.empty(alice, bob)
        assertEquals("", empty.toString())
    }

    @Test
    fun `verify that toString() of a edge with two components matches our expectations`() {
        val twoCerts = Edge.fromCertification(aliceSignsBob)
        twoCerts.add(aliceSignsBobUserId)

        assertEquals("A certifies binding: null <-> B [120]\n" +
                "A certifies binding: Bob <bob@example.org> <-> B [120]", twoCerts.toString())
    }
    
    @Test
    fun `verify that for multiple components over the same datum, only the most recent components are preserved`() {
        val now = Date()
        val fiveSecondsBefore = Date(now.time - 5000)
        val old = EdgeComponent(alice, bob, "Bob <bob@example.org>", fiveSecondsBefore)
        val new = EdgeComponent(alice, bob, "Bob <bob@example.org>", now)
        val new2 = EdgeComponent(alice, bob, "Bob <bob@example.org>", now, null, true, 44, Depth.auto(10), RegexSet.wildcard())

        var set = Edge(alice, bob, mapOf())
        set.add(old)

        assertEquals(listOf(old), set.components["Bob <bob@example.org>"])

        set.add(new)
        assertEquals(listOf(new), set.components["Bob <bob@example.org>"])

        set.add(new2)
        assertEquals(listOf(new, new2), set.components["Bob <bob@example.org>"])

        set.add(old)
        assertEquals(listOf(new, new2), set.components["Bob <bob@example.org>"])
    }
}