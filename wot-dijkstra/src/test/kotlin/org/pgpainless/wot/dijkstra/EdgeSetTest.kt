// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.network.*
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EdgeSetTest {

    private val alice = Node(Fingerprint("A"), null, RevocationState.notRevoked(), mapOf())
    private val bob = Node(Fingerprint("B"), null, RevocationState.notRevoked(), mapOf())
    private val charlie = Node(Fingerprint("C"), null, RevocationState.notRevoked(), mapOf())

    private val aliceSignsBob = Edge(alice, bob, null, Date())
    private val aliceSignsBobUserId = Edge(alice, bob, "Bob <bob@example.org>", Date())
    private val aliceSignsCharlie = Edge(alice, charlie, null, Date())
    private val charlieSignsBob = Edge(charlie, bob, null, Date())

    @Test
    fun `verify that properties of an empty CertificationSet are also empty`() {
        val empty = EdgeSet.empty(alice, bob)
        assert(empty.certifications.isEmpty())
        assertEquals(alice, empty.issuer)
        assertEquals(bob, empty.target)
    }

    @Test
    fun `verify that add()ing Certification objects works if issuer and target match that of the CertificationSet`() {
        val set = EdgeSet.empty(alice, bob)

        set.add(aliceSignsBob)
        assertTrue {
            set.certifications.values.any {
                it.contains(aliceSignsBob)
            }
        }
        set.add(aliceSignsBobUserId)
        assertTrue {
            set.certifications["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId)
        }
    }

    @Test
    fun `verify that add()ing another Certification object fails if the issuer mismatches`() {
        val set = EdgeSet.empty(alice, bob)
        assertThrows<IllegalArgumentException> { set.add(charlieSignsBob) }
    }

    @Test
    fun `verify that add()ing another Certification object fails if the target mismatches`() {
        val set = EdgeSet.empty(alice, bob)
        assertThrows<IllegalArgumentException> { set.add(aliceSignsCharlie) }
    }

    @Test
    fun `verify that merge()ing another CertificationSet works if issuer and target match that of the CertificationSet`() {
        val set = EdgeSet.fromCertification(aliceSignsBob)
        val others = EdgeSet.fromCertification(aliceSignsBobUserId)

        set.merge(others)
        assertEquals(2, set.certifications.size)
        assertTrue { set.certifications[null]!!.contains(aliceSignsBob) }
        assertTrue { set.certifications["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId) }
    }

    @Test
    fun `verify that merge()ing another CertificationSet with mismatched issuer fails`() {
        val set = EdgeSet.fromCertification(aliceSignsBob)
        val issuerMismatch = EdgeSet.fromCertification(charlieSignsBob)

        assertThrows<IllegalArgumentException> { set.merge(issuerMismatch) }
    }

    @Test
    fun `verify that merge()ing another CertificationSet with mismatched target fails`() {
        val set = EdgeSet.fromCertification(aliceSignsBob)
        val targetMismatch = EdgeSet.fromCertification(aliceSignsCharlie)

        assertThrows<IllegalArgumentException> { set.merge(targetMismatch) }
    }

    @Test
    fun `verify that merge()ing a CertificationSet with itself is idempotent`() {
        val set = EdgeSet.fromCertification(aliceSignsBob)
        assertEquals(1, set.certifications.size)
        set.merge(set)
        assertEquals(1, set.certifications.size)
    }

    @Test
    fun `verify that toString() of an empty CertificationSet is the empty string`() {
        val empty = EdgeSet.empty(alice, bob)
        assertEquals("", empty.toString())
    }

    @Test
    fun `verify that toString() of a CertificationSet with two Certifications matches our expectations`() {
        val twoCerts = EdgeSet.fromCertification(aliceSignsBob)
        twoCerts.add(aliceSignsBobUserId)

        assertEquals("A certifies binding: null <-> B [120]\n" +
                "A certifies binding: Bob <bob@example.org> <-> B [120]", twoCerts.toString())
    }
    
    @Test
    fun `verify that for multiple Certifications over the same datum, only the most recent certifications are preserved`() {
        val now = Date()
        val fiveSecondsBefore = Date(now.time - 5000)
        val old = Edge(alice, bob, "Bob <bob@example.org>", fiveSecondsBefore)
        val new = Edge(alice, bob, "Bob <bob@example.org>", now)
        val new2 = Edge(alice, bob, "Bob <bob@example.org>", now, null, true, 44, Depth.auto(10), RegexSet.wildcard())

        var set = EdgeSet(alice, bob, mapOf())
        set.add(old)

        assertEquals(listOf(old), set.certifications["Bob <bob@example.org>"])

        set.add(new)
        assertEquals(listOf(new), set.certifications["Bob <bob@example.org>"])

        set.add(new2)
        assertEquals(listOf(new, new2), set.certifications["Bob <bob@example.org>"])

        set.add(old)
        assertEquals(listOf(new, new2), set.certifications["Bob <bob@example.org>"])
    }
}