package org.pgpainless.wot.dijkstra.sq;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DepthTest {

    @Test
    public void testUnlimitedItem() {
        Depth depth = Depth.unconstrained();
        assertTrue(depth.isUnconstrained());
        assertFalse(depth.getLimit().isPresent());
    }

    @Test
    public void testLimitedItem() {
        Depth limited = Depth.limited(2);
        assertFalse(limited.isUnconstrained());
        assertTrue(limited.getLimit().isPresent());
        assertEquals(2, limited.getLimit().get());
    }

    @Test
    public void testDecreaseUnconstrainedYieldsUnconstrained() {
        Depth unconstrained = Depth.unconstrained();
        Depth decreased = unconstrained.decrease(20);
        assertTrue(decreased.isUnconstrained());
    }

    @Test
    public void testDecreaseLimitedYieldsDecreasedLimited() {
        Depth limited = Depth.limited(1);
        Depth decreased = limited.decrease(1);
        assertFalse(decreased.isUnconstrained());
        assertEquals(0, decreased.getLimit().get());
    }

    @Test
    public void testDecreaseLimitedTooMuchYieldsException() {
        Depth limited = Depth.limited(0);
        assertThrows(IllegalArgumentException.class, () -> limited.decrease(1));
    }

    @Test
    public void testCompareTo() {
        Depth unlimited = Depth.unconstrained();
        Depth unlimited2 = Depth.unconstrained();
        Depth depth2 = Depth.limited(2);
        Depth depth2_ = Depth.limited(2);
        Depth depth5 = Depth.limited(5);

        assertEquals(0, unlimited.compareTo(unlimited2));
        assertTrue(unlimited.compareTo(depth2) > 0);
        assertTrue(unlimited.compareTo(depth5) > 0);
        assertTrue(depth2.compareTo(unlimited) < 0);
        assertTrue(depth2.compareTo(depth5) < 0);
        assertTrue(depth5.compareTo(depth2) > 0);
        assertEquals(0, depth2.compareTo(depth2_));
    }

    @Test
    public void testAutoUnconstrained() {
        Depth depth = Depth.auto(255);
        assertTrue(depth.isUnconstrained());
    }

    @Test
    public void testAutoLimited() {
        Depth depth = Depth.auto(120);
        assertFalse(depth.isUnconstrained());
        assertEquals(120, depth.getLimit().get());
    }

    @Test
    public void testOutOfBounds() {
        assertThrows(IllegalArgumentException.class, () -> Depth.limited(-1));
        assertThrows(IllegalArgumentException.class, () -> Depth.limited(256));
        assertThrows(IllegalArgumentException.class, () -> Depth.auto(-1));
        assertThrows(IllegalArgumentException.class, () -> Depth.auto(256));
    }

    @Test
    public void testToStringUnconstrained() {
        assertEquals("unconstrained", Depth.unconstrained().toString());
    }

    @Test
    public void testToStringLimited() {
        assertEquals("1", Depth.limited(1).toString());
    }
}
