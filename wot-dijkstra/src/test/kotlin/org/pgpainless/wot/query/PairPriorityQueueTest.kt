// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import kotlin.test.Test
import kotlin.test.assertEquals

class PairPriorityQueueTest {

    @Test
    fun simple1() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        pq.insertOrUpdate(0, 0);
        pq.insertOrUpdate(1, 1);
        pq.insertOrUpdate(2, 2);
        pq.insertOrUpdate(3, 3);
        pq.insertOrUpdate(4, 4);
        pq.insertOrUpdate(5, 5);

        assertEquals(Pair(0, 0), pq.pop());
        assertEquals(Pair(1, 1), pq.pop());
        assertEquals(Pair(2, 2), pq.pop());
        assertEquals(Pair(3, 3), pq.pop());
        assertEquals(Pair(4, 4), pq.pop());
        assertEquals(Pair(5, 5), pq.pop());

        assertEquals(null, pq.pop());
        assertEquals(null, pq.pop());
    }

    @Test
    fun simple2() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        pq.insertOrUpdate(0, 0);
        pq.insertOrUpdate(1, -1);
        pq.insertOrUpdate(2, -2);
        pq.insertOrUpdate(3, -3);
        pq.insertOrUpdate(4, -4);
        pq.insertOrUpdate(5, -5);

        assertEquals(Pair(5, -5), pq.pop());
        assertEquals(Pair(4, -4), pq.pop());
        assertEquals(Pair(3, -3), pq.pop());
        assertEquals(Pair(2, -2), pq.pop());
        assertEquals(Pair(1, -1), pq.pop());
        assertEquals(Pair(0, 0), pq.pop());

        assertEquals(null, pq.pop());
        assertEquals(null, pq.pop());
    }

    @Test
    fun simple3() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        pq.insertOrUpdate(0, 0);
        pq.insertOrUpdate(1, 1);
        pq.insertOrUpdate(5, 5);
        pq.insertOrUpdate(2, 2);
        pq.insertOrUpdate(4, 4);
        pq.insertOrUpdate(3, 3);

        assertEquals(Pair(0, 0), pq.pop());
        assertEquals(Pair(1, 1), pq.pop());
        assertEquals(Pair(2, 2), pq.pop());
        assertEquals(Pair(3, 3), pq.pop());
        assertEquals(Pair(4, 4), pq.pop());
        assertEquals(Pair(5, 5), pq.pop());
        assertEquals(null, pq.pop());
        assertEquals(null, pq.pop());
    }

    @Test
    fun simple4() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();
        assertEquals(null, pq.pop());

        pq.insertOrUpdate(0, 0);
        pq.insertOrUpdate(0, 0);
        assertEquals(Pair(0, 0), pq.pop());
        assertEquals(null, pq.pop());
    }

    @Test
    fun simple5() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();
        assertEquals(null, pq.pop());

        pq.insertOrUpdate(0, 0);
        pq.insertOrUpdate(0, 0);
        assertEquals(Pair(0, 0), pq.pop());
        pq.insertOrUpdate(0, 0);
        assertEquals(Pair(0, 0), pq.pop());
        assertEquals(null, pq.pop());
    }


    @Test
    fun duplicates() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        // Insert different keys with value i.
        for (i in 19 downTo 0) {
            pq.insertOrUpdate(i, i);
        }
        // Insert the same keys with  lower value `i-1`.
        // This should overwrite the old keys.
        for (i in 19 downTo 0) {
            pq.insertOrUpdate(i, i - 1);
        }

        // Insert the same keys with a higher value.
        // These should be ignored.
        for (i in 19 downTo 0) {
            pq.insertOrUpdate(i, i);
        }

        for (i in 0 until 20) {
            assertEquals(Pair(i, i - 1), pq.pop());
        }
        assertEquals(null, pq.pop());
        assertEquals(null, pq.pop());
    }

    @Test
    fun insert_pop() {
        val pq: PairPriorityQueue<Int, Int> = PairPriorityQueue();

        // Insert different keys with value i+1.
        for (i in 9 downTo 0) {
            pq.insertOrUpdate(i, i + 1);
        }
        // Insert the same keys with their own value. This should
        // overwrite the old keys.
        for (i in 0 until 10) {
            pq.insertOrUpdate(i, i);
            assertEquals(Pair(i, i), pq.pop());
        }
        assertEquals(null, pq.pop());
        assertEquals(null, pq.pop());
    }
}