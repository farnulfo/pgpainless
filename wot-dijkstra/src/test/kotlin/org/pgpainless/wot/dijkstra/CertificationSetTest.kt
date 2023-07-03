// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dijkstra.sq.*
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CertificationSetTest {

    private val alice = CertSynopsis(Fingerprint("0000000000000000000000000000000000000000"), null, RevocationState.notRevoked(), mapOf())
    private val bob = CertSynopsis(Fingerprint("1111111111111111111111111111111111111111"), null, RevocationState.notRevoked(), mapOf())
    private val charlie = CertSynopsis(Fingerprint("2222222222222222222222222222222222222222"), null, RevocationState.notRevoked(), mapOf())

    private val aliceSignsBob = Certification(alice, null, bob, Date())
    private val aliceSignsBobUserId = Certification(alice, "Bob <bob@example.org>", bob, Date())
    private val aliceSignsCharlie = Certification(alice, null, charlie, Date())
    private val charlieSignsBob = Certification(charlie, null, bob, Date())

    @Test
    fun `verify that properties of an empty CertificationSet are also empty`() {
        val empty = CertificationSet.empty(alice, bob)
        assert(empty.certifications.isEmpty())
        assertEquals(alice, empty.issuer)
        assertEquals(bob, empty.target)
    }

    @Test
    fun `verify that add()ing Certification objects works if issuer and target match that of the CertificationSet`() {
        val set = CertificationSet.empty(alice, bob)

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
        val set = CertificationSet.empty(alice, bob)
        assertThrows<IllegalArgumentException> { set.add(charlieSignsBob) }
    }

    @Test
    fun `verify that add()ing another Certification object fails if the target mismatches`() {
        val set = CertificationSet.empty(alice, bob)
        assertThrows<IllegalArgumentException> { set.add(aliceSignsCharlie) }
    }

    @Test
    fun `verify that merge()ing another CertificationSet works if issuer and target match that of the CertificationSet`() {
        val set = CertificationSet.fromCertification(aliceSignsBob)
        val others = CertificationSet.fromCertification(aliceSignsBobUserId)

        set.merge(others)
        assertEquals(2, set.certifications.size)
        assertTrue { set.certifications[null]!!.contains(aliceSignsBob) }
        assertTrue { set.certifications["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId) }
    }

    @Test
    fun `verify that merge()ing another CertificationSet with mismatched issuer fails`() {
        val set = CertificationSet.fromCertification(aliceSignsBob)
        val issuerMismatch = CertificationSet.fromCertification(charlieSignsBob)

        assertThrows<IllegalArgumentException> { set.merge(issuerMismatch) }
    }

    @Test
    fun `verify that merge()ing another CertificationSet with mismatched target fails`() {
        val set = CertificationSet.fromCertification(aliceSignsBob)
        val targetMismatch = CertificationSet.fromCertification(aliceSignsCharlie)

        assertThrows<IllegalArgumentException> { set.merge(targetMismatch) }
    }

    @Test
    fun `verify that merge()ing a CertificationSet with itself is idempotent`() {
        val set = CertificationSet.fromCertification(aliceSignsBob)
        assertEquals(1, set.certifications.size)
        set.merge(set)
        assertEquals(1, set.certifications.size)
    }

    @Test
    fun `verify that toString() of an empty CertificationSet is the empty string`() {
        val empty = CertificationSet.empty(alice, bob)
        assertEquals("", empty.toString())
    }

    @Test
    fun `verify that toString() of a CertificationSet with two Certifications matches our expectations`() {
        val twoCerts = CertificationSet.fromCertification(aliceSignsBob)
        twoCerts.add(aliceSignsBobUserId)

        assertEquals("0000000000000000000000000000000000000000 delegates to 1111111111111111111111111111111111111111\n" +
                "0000000000000000000000000000000000000000 certifies [Bob <bob@example.org>] 1111111111111111111111111111111111111111", twoCerts.toString())
    }
}