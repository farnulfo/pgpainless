// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.wot.network.Depth.Companion.auto
import org.pgpainless.wot.network.Depth.Companion.limited
import org.pgpainless.wot.network.Depth.Companion.unconstrained
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DepthTest {

    @Test
    fun `verify Depth#unconstrained() is in fact unconstrained`() {
        val depth = unconstrained()
        assert(depth.isUnconstrained())
    }

    @Test
    fun `verify Depth#unconstrained() has null depth`() {
        val depth = unconstrained()
        assert(depth.isUnconstrained())
        assertEquals(depth.value(), 255)
    }

    @Test
    fun `verify Depth#limited(2) initializes properly`() {
        val limited = limited(2)
        assert(!limited.isUnconstrained())
        assertEquals(2, limited.value())
    }

    @Test
    fun `verify Depth#limited(X) is not unconstrained`() {
        val limited = limited(1)
        assertFalse(limited.isUnconstrained())
    }

    @Test
    fun `verify that decrease()ing an unconstrained Depth is an idempotent operation`() {
        val unconstrained = unconstrained()
        val decreased = unconstrained.decrease(20)
        assertTrue(decreased.isUnconstrained())
    }

    @Test
    fun `verify that decrease()ing a limited Depth yields a properly decreased result`() {
        val limited = limited(3)
        val decreased = limited.decrease(2)
        assertFalse(decreased.isUnconstrained())
        assertEquals(1, decreased.value())
    }

    @Test
    fun `verify that decrease()ing a Depth object by a value greater than its current value fails`() {
        assertThrows<IllegalArgumentException> { limited(0).decrease(1) }
        assertThrows<IllegalArgumentException> { limited(1).decrease(2) }
        assertThrows<IllegalArgumentException> { limited(17).decrease(42) }
    }

    @Test
    fun `verify proper function of compareTo()`() {
        val unlimited = unconstrained()
        val depth2 = limited(2)
        val depth5 = limited(5)
        assertTrue(unlimited > 0)
        assertTrue(unlimited > 255)
        assertTrue(unlimited > 256)

        assertTrue(depth2 > 0)
        assertTrue(depth2 > 1)
        assertFalse(depth2 > 2)
        assertFalse(depth2 > 256)

        assertTrue(depth5 > 1)
        assertTrue(depth5 > 4)
        assertFalse(depth5 > 5)
        assertFalse(depth5 > 256)
    }

    @Test
    fun `verify that min() of a Depth with itself yields itself`() {
        val limit = limited(17)
        assertEquals(limit, limit.min(limit))
    }

    @Test
    fun `verify that min() of two limited values returns the smaller one`() {
        val limit1 = limited(1)
        val limit4 = limited(4)

        assertEquals(limit1, limit1.min(limit4))
        assertEquals(limit1, limit4.min(limit1))
    }

    @Test
    fun `verify that min() of a limited and an unconstrained value yields the limited value`() {
        val limit0 = limited(0)
        val limit1 = limited(1)
        assertEquals(limit0, unconstrained().min(limit0))
        assertEquals(limit1, limit1.min(unconstrained()))
    }

    @Test
    fun `verify that the min() of unconstrained and unconstrained is unconstrained`() {
        val unconstrained = unconstrained()
        assertEquals(unconstrained, unconstrained.min(unconstrained))
    }

    @Test
    fun `verify that Depth#auto(255) yields an unconstrained Depth`() {
        assertTrue { auto(255).isUnconstrained() }
        assertEquals(auto(255).value(), 255)
    }

    @Test
    fun `verify that Depth#auto(X) for values from 0 to 254 yield limited Depth objects`() {
        assertFalse { auto(0).isUnconstrained() }
        assertFalse { auto(120).isUnconstrained() }
        assertFalse { auto(254).isUnconstrained() }

        assertNotNull(auto(42).value())
    }

    @Test
    fun `verify that depth values out of the range from 0 to 255 yield failures`() {
        assertThrows<IllegalArgumentException> { limited(-1) }
        assertThrows<IllegalArgumentException> { limited(256) }
        assertThrows<IllegalArgumentException> { auto(-1) }
        assertThrows<IllegalArgumentException> { auto(256) }
    }

    @Test
    fun `verify that toString() of Depth#unconstrained() returns the String 'unconstrained'`() {
        assertEquals("unconstrained", unconstrained().toString())
    }

    @Test
    fun `verify that toString() of a limited Depth returns the String of its value`() {
        assertEquals("1", limited(1).toString())
        assertEquals("42", limited(42).toString())
    }
}