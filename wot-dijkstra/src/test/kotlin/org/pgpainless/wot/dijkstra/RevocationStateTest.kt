package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.ReferenceTime
import org.pgpainless.wot.dijkstra.sq.RevocationState
import java.util.*
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RevocationStateTest {

    @Test
    fun testNotRevoked() {
        val notRevoked = RevocationState.notRevoked()
        assertTrue { notRevoked.isNotRevoked() }
        assertFalse { notRevoked.isSoftRevocation() }
        assertFalse { notRevoked.isHardRevocation() }
        assertFalse { notRevoked.isEffective(ReferenceTime.timestamp(Date())) }
    }

    @Test
    fun testSoftRevocation() {
        val timestamp = Date()
        val before = Date(timestamp.time - 5000)
        val after = Date(timestamp.time + 5000)
        val softRevoked = RevocationState.softRevoked(timestamp)

        assertTrue { softRevoked.isSoftRevocation() }
        assertFalse { softRevoked.isHardRevocation() }
        assertFalse { softRevoked.isNotRevoked() }
        assertTrue { softRevoked.isEffective(ReferenceTime.timestamp(after)) }
        assertFalse { softRevoked.isEffective(ReferenceTime.timestamp(before)) }
    }

    @Test
    fun testHardRevoked() {
        val hardRevoked = RevocationState.hardRevoked()
        assertTrue { hardRevoked.isHardRevocation() }
        assertFalse { hardRevoked.isSoftRevocation() }
        assertFalse { hardRevoked.isNotRevoked() }
        assertTrue { hardRevoked.isEffective(ReferenceTime.now()) }
    }
}