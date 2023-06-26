package org.pgpainless.wot.dijkstra

import java.util.PriorityQueue

/**
 * A de-duplicating max-priority queue for key-value pairs.
 *
 * When an element is popped, the queue entry with the *largest value*
 * is popped (if there are multiple elements with the same max value,
 * one of them is returned.)
 *
 * When inserting an element, if there is already an element with the same
 * key, the element with the larger value is kept.
 */
internal class PairPriorityQueue<K, V : Comparable<V>>() {

    // NOTE: This implementation is not optimized for efficient inserts!
    // - Each insert() involves a linear search by key
    // - Each insert() sorts eagerly (via j.u.PriorityQueue.add())

    private val pq: PriorityQueue<Pair<K, V>> = PriorityQueue {
        // Order priority queue entries by value (max first)
        o1, o2 ->
        o2.second.compareTo(o1.second)
    }

    fun insert(key: K, value: V) {
        when (val element = pq.find { it.first == key }) {
            null -> pq.add(Pair(key, value)) // Add as a new element
            else -> {
                // If the new value is bigger: replace the element
                if (value > element.second) {
                    pq.remove(element)
                    pq.add(Pair(key, value))
                }
            }
        }
    }

    fun pop(): Pair<K, V>? = pq.poll()
}