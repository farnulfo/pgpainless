package org.pgpainless.wot.dijkstra

import org.pgpainless.wot.query.PairPriorityQueue
import kotlin.test.Test
import kotlin.test.assertEquals

// Priority queue tests.

// Test data from `sequoia-wot:src/priority_queue.rs`.
class PriorityQueueTest {

    @Test
    fun simple1() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        pq.insert(0, 0);
        pq.insert(1, 1);
        pq.insert(2, 2);
        pq.insert(3, 3);
        pq.insert(4, 4);
        pq.insert(5, 5);

        assertEquals(pq.pop(), Pair(5, 5));
        assertEquals(pq.pop(), Pair(4, 4));
        assertEquals(pq.pop(), Pair(3, 3));
        assertEquals(pq.pop(), Pair(2, 2));
        assertEquals(pq.pop(), Pair(1, 1));
        assertEquals(pq.pop(), Pair(0, 0));
        assertEquals(pq.pop(), null);
        assertEquals(pq.pop(), null);
    }

    @Test
    fun simple2() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        pq.insert(0, 0);
        pq.insert(1, -1);
        pq.insert(2, -2);
        pq.insert(3, -3);
        pq.insert(4, -4);
        pq.insert(5, -5);

        assertEquals(pq.pop(), Pair(0, 0));
        assertEquals(pq.pop(), Pair(1, -1));
        assertEquals(pq.pop(), Pair(2, -2));
        assertEquals(pq.pop(), Pair(3, -3));
        assertEquals(pq.pop(), Pair(4, -4));
        assertEquals(pq.pop(), Pair(5, -5));
        assertEquals(pq.pop(), null);
        assertEquals(pq.pop(), null);
    }

    @Test
    fun simple3() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        pq.insert(0, 0);
        pq.insert(1, 1);
        pq.insert(5, 5);
        pq.insert(2, 2);
        pq.insert(4, 4);
        pq.insert(3, 3);

        assertEquals(pq.pop(), Pair(5, 5));
        assertEquals(pq.pop(), Pair(4, 4));
        assertEquals(pq.pop(), Pair(3, 3));
        assertEquals(pq.pop(), Pair(2, 2));
        assertEquals(pq.pop(), Pair(1, 1));
        assertEquals(pq.pop(), Pair(0, 0));
        assertEquals(pq.pop(), null);
        assertEquals(pq.pop(), null);
    }

    @Test
    fun simple4() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();
        assertEquals(pq.pop(), null);

        pq.insert(0, 0);
        pq.insert(0, 0);
        assertEquals(pq.pop(), Pair(0, 0));
        assertEquals(pq.pop(), null);
    }

    @Test
    fun simple5() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();
        assertEquals(pq.pop(), null);

        pq.insert(0, 0);
        pq.insert(0, 0);
        assertEquals(pq.pop(), Pair(0, 0));
        pq.insert(0, 0);
        assertEquals(pq.pop(), Pair(0, 0));
        assertEquals(pq.pop(), null);
    }


    @Test
    fun duplicates() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        // Insert different keys with the same value.
        for (i in 0 until 20) {
            pq.insert(i, 0);
        }
        // Insert the same keys with their own value.  This should
        // overwrite the old keys.
        for (i in 0 until 20) {
            pq.insert(i, i);
        }

        // Insert different keys with the same value.
        for (i in 0 until 20) {
            pq.insert(i, 0);
        }

        for (i in 19 downTo 0) {
            assertEquals(pq.pop(), Pair(i, i));
        }
        assertEquals(pq.pop(), null);
        assertEquals(pq.pop(), null);
    }

    @Test
    fun insert_pop() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        // Insert different keys with the same value.
        for (i in 0 until 10) {
            pq.insert(i, 0);
        }
        // Insert the same keys with their own value.  This should
        // overwrite the old keys.
        for (i in 9 downTo 0) {
            pq.insert(i, i);
            assertEquals(pq.pop(), Pair(i, i));
        }
        assertEquals(pq.pop(), null);
        assertEquals(pq.pop(), null);
    }
}
