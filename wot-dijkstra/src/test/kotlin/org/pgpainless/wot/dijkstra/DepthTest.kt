// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.dijkstra.sq.Depth.Companion.auto
import org.pgpainless.wot.dijkstra.sq.Depth.Companion.limited
import org.pgpainless.wot.dijkstra.sq.Depth.Companion.unconstrained
import kotlin.test.*

class DepthTest {

    @Test
    fun testUnlimitedItem() {
        val depth = unconstrained()
        assert(depth.isUnconstrained())
        assertNull(depth.limit)
    }

    @Test
    fun testLimitedItem() {
        val limited = limited(2)
        assertFalse(limited.isUnconstrained())
        assertNotNull(limited.limit)
        assertEquals(2, limited.limit)
    }

    @Test
    fun testDecreaseUnconstrainedYieldsUnconstrained() {
        val unconstrained = unconstrained()
        val decreased = unconstrained.decrease(20)
        assertTrue(decreased.isUnconstrained())
    }

    @Test
    fun testDecreaseLimitedYieldsDecreasedLimited() {
        val limited = limited(1)
        val decreased = limited.decrease(1)
        assertFalse(decreased.isUnconstrained())
        assertEquals(0, decreased.limit)
    }

    @Test
    fun testDecreaseLimitedTooMuchYieldsException() {
        val limited = limited(0)
        assertThrows<IllegalArgumentException> { limited.decrease(1) }
    }

    @Test
    fun testCompareTo() {
        val unlimited = unconstrained()
        val unlimited2 = unconstrained()
        val depth2 = limited(2)
        val depth2_ = limited(2)
        val depth5 = limited(5)
        assertEquals(0, unlimited.compareTo(unlimited2))
        assertTrue(unlimited.compareTo(depth2) > 0)
        assertTrue(unlimited.compareTo(depth5) > 0)
        assertTrue(depth2.compareTo(unlimited) < 0)
        assertTrue(depth2.compareTo(depth5) < 0)
        assertTrue(depth5.compareTo(depth2) > 0)
        assertEquals(0, depth2.compareTo(depth2_))
    }

    @Test
    fun testAutoUnconstrained() {
        val depth = auto(255)
        assertTrue(depth.isUnconstrained())
    }

    @Test
    fun testAutoLimited() {
        val depth = auto(120)
        assertFalse(depth.isUnconstrained())
        assertEquals(120, depth.limit)
    }

    @Test
    fun testOutOfBounds() {
        assertThrows<IllegalArgumentException> { limited(-1) }
        assertThrows<IllegalArgumentException> { limited(256) }
        assertThrows<IllegalArgumentException> { auto(-1) }
        assertThrows<IllegalArgumentException> { auto(256) }
    }

    @Test
    fun testToStringUnconstrained() {
        assertEquals("unconstrained", unconstrained().toString())
    }

    @Test
    fun testToStringLimited() {
        assertEquals("1", limited(1).toString())
    }
}