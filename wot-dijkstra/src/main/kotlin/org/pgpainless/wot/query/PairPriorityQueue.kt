package org.pgpainless.wot.query

import java.util.*

/**
 * A de-duplicating min-priority queue for key-value pairs.
 *
 * When an element is popped, the queue entry with the *most desirable
 * value* (that is: low cost) is popped (if there are multiple elements
 * with the same minimal value, one of them is returned.)
 *
 * When inserting an element, if there is already an element with the same
 * key, the element with the smaller value is kept.
 */
internal class PairPriorityQueue<K, V : Comparable<V>>() {

    // NOTE: This implementation is not optimized for efficient inserts!
    // - Each insert() involves a linear search by key
    // - Each insert() sorts eagerly (via j.u.PriorityQueue.add())

    private val pq: PriorityQueue<Pair<K, V>> = PriorityQueue { o1, o2 ->
        // Order priority queue entries by value (min first)
        o1.second.compareTo(o2.second)
    }

    fun insertOrUpdate(key: K, value: V) {
        when (val element = pq.find { it.first == key }) {
            null -> pq.add(Pair(key, value)) // Add as a new element
            else -> {
                // If the new value is "cheaper": replace the element
                if (value < element.second) {
                    pq.remove(element)
                    pq.add(Pair(key, value))
                }
            }
        }
    }

    fun pop(): Pair<K, V>? = pq.poll()
}