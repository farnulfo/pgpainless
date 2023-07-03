package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.ReferenceTime
import org.pgpainless.wot.dijkstra.sq.RevocationState
import java.util.*
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RevocationStateTest {

    @Test
    fun `verify that RevocationState#notRevoked() is - well - not revoked`() {
        val notRevoked = RevocationState.notRevoked()
        assertTrue("Non-revocation is not revoked") { notRevoked.isNotRevoked() }
    }

    @Test
    fun `verify that RevocationState#notRevoked() is not an effective revocation`() {
        assertFalse("Non-revocation MUST NOT be effective at any time") {
            RevocationState.notRevoked().isEffective(ReferenceTime.timestamp(Date()))
        }
    }

    @Test
    fun `verify that RevocationState#notRevoked() is neither a hard, nor a soft revocation`() {
        val notRevoked = RevocationState.notRevoked()
        assertFalse("Non-revocation MUST NOT be soft") { notRevoked.isSoftRevocation() }
        assertFalse("Non-revocation MUST NOT be hard") { notRevoked.isHardRevocation() }
    }

    @Test
    fun `verify that a soft revocation is not hard and not not-revoked`() {
        val softRevoked = RevocationState.softRevoked(Date())
        assertTrue("Soft revocation MUST be soft") { softRevoked.isSoftRevocation() }
        assertFalse("Soft revocation MUST NOT be hard") { softRevoked.isHardRevocation() }
        assertFalse("Soft revocation MUST NOT be not-revoked") { softRevoked.isNotRevoked() }
    }

    @Test
    fun `verify that a soft revocation is effective at its creation`() {
        val creationTime = Date()
        val softRevoked = RevocationState.softRevoked(creationTime)

        assertTrue("Soft revocation MUST be effective at its creation time") {
            softRevoked.isEffective(ReferenceTime.timestamp(creationTime))
        }
    }

    @Test
    fun `verify that a soft revocation is effective after its creation`() {
        val creationTime = Date()
        val softRevoked = RevocationState.softRevoked(creationTime)

        val after = Date(creationTime.time + 5000) // 5 seconds after creation

        assertTrue("Soft revocation MUST be effective after its creation time") {
            softRevoked.isEffective(ReferenceTime.timestamp(after))
        }
    }

    @Test
    fun `verify that a soft revocation is not effective before its creation`() {
        val creationTime = Date()
        val softRevoked = RevocationState.softRevoked(creationTime)

        val before = Date(creationTime.time - 5000) // 5 seconds before creation

        assertFalse("Soft revocation MUST NOT be effective before its creation time") {
            softRevoked.isEffective(ReferenceTime.timestamp(before))
        }
    }

    @Test
    fun `verify that a hard revocation is neither soft nor non-revoked`() {
        val hardRevoked = RevocationState.hardRevoked()
        assertTrue("Hard revocation MUST be hard") { hardRevoked.isHardRevocation() }
        assertFalse("Hard revocation MUST NOT be soft") { hardRevoked.isSoftRevocation() }
        assertFalse("Hard revocation MUST NOT be not-revoked") { hardRevoked.isNotRevoked() }
    }

    @Test
    fun `verify that a hard revocation is effective at any point in time`() {
        assertTrue("Hard revocation MUST be effective at the earliest possible date") {
            RevocationState.hardRevoked().isEffective(ReferenceTime.timestamp(Date(0L)))
        }
        assertTrue("Hard revocation MUST be effective 5 seconds ago") {
            RevocationState.hardRevoked().isEffective(ReferenceTime.timestamp(Date(Date().time - 5000)))
        }
        assertTrue("Hard revocation MUST be effective right now") {
            RevocationState.hardRevoked().isEffective(ReferenceTime.now())
        }
        assertTrue("Hard revocation MUST be effective in 5 seconds time") {
            RevocationState.hardRevoked().isEffective(ReferenceTime.timestamp(Date(Date().time + 5000)))
        }
        assertTrue("Hard revocation MUST be effective at the farthest possible date") {
            RevocationState.hardRevoked().isEffective(ReferenceTime.timestamp(Date(Long.MAX_VALUE)))
        }
    }
}