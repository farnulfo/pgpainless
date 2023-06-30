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
    fun emptyCertificationSet() {
        val empty = CertificationSet.empty(alice, bob)
        assertTrue { empty.certifications.isEmpty() }
        assertEquals(alice, empty.issuer)
        assertEquals(bob, empty.target)
    }

    @Test
    fun addCertification() {
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

        assertThrows<IllegalArgumentException> { set.add(charlieSignsBob) }
        assertThrows<IllegalArgumentException> { set.add(aliceSignsCharlie) }
    }

    @Test
    fun mergeCertificationSets() {
        val set = CertificationSet.fromCertification(aliceSignsBob)
        val others = CertificationSet.fromCertification(aliceSignsBobUserId)
        val mismatch = CertificationSet.fromCertification(charlieSignsBob)

        set.merge(others)
        assertEquals(2, set.certifications.size)
        assertTrue { set.certifications[null]!!.contains(aliceSignsBob) }
        assertTrue { set.certifications["Bob <bob@example.org>"]!!.contains(aliceSignsBobUserId) }

        assertThrows<IllegalArgumentException> { set.merge(mismatch) }

        set.merge(set)
        assertEquals(2, set.certifications.size)
    }

    @Test
    fun testToString() {
        val empty = CertificationSet.empty(alice, bob)
        assertEquals("", empty.toString())

        val twoCerts = CertificationSet.fromCertification(aliceSignsBob)
        twoCerts.add(aliceSignsBobUserId)

        assertEquals("0000000000000000000000000000000000000000 delegates to 1111111111111111111111111111111111111111\n" +
                "0000000000000000000000000000000000000000 certifies [Bob <bob@example.org>] 1111111111111111111111111111111111111111", twoCerts.toString())
    }
}