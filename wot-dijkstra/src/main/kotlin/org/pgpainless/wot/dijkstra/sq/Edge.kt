// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

/**
 * An [Edge] is a set of [components][EdgeComponent] made by the same issuer, on the same
 * target.
 *
 * @param issuer origin node
 * @param target target node
 * @param components [Map] keyed by datum, whose values are [Lists][List] of
 * [EdgeComponents][EdgeComponent] that are calculated over the key datum.
 * Note, that the key can also be null for [EdgeComponents][EdgeComponent] over the targets primary key.
 */
class Edge(
        val issuer: Node,
        val target: Node,
        components: Map<String?, List<EdgeComponent>>) {

    init {
        components.forEach { (_, certifications) ->
            certifications.forEach {
                add(it)
            }
        }
    }

    private val _components: MutableMap<String?, MutableList<EdgeComponent>> = mutableMapOf()
    val components: Map<String?, List<EdgeComponent>>
        get() = _components.toMutableMap()

    companion object {

        /**
         * Create an empty [Edge] with no [components][EdgeComponent].
         *
         * @param issuer the certificate that issued the [EdgeComponents][EdgeComponent].
         * @param target the certificate that is targeted by the [EdgeComponents][EdgeComponent].
         */
        @JvmStatic
        fun empty(issuer: Node, target: Node): Edge {
            return Edge(issuer, target, HashMap())
        }

        /**
         * Create a [Edge] from a single [EdgeComponent].
         *
         * @param certification certification
         */
        @JvmStatic
        fun fromCertification(certification: EdgeComponent): Edge {
            val set = empty(certification.issuer, certification.target)
            set.add(certification)
            return set
        }
    }

    /**
     * Merge the given [Edge] into this.
     * This method copies all [EdgeComponents][EdgeComponent] from the other [Edge] into [components].
     *
     * @param other [Edge] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun merge(other: Edge) {
        if (other == this) {
            return
        }

        require(issuer.fingerprint == other.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == other.target.fingerprint) { "Target fingerprint mismatch." }

        for (userId in other.components.keys) {
            for (certification in other.components[userId]!!) {
                add(certification)
            }
        }
    }

    /**
     * Add a single [EdgeComponent] into this objects [components].
     * Adding multiple [EdgeComponents][EdgeComponent] for the same datum, but with different creation times results in
     * only the most recent [EdgeComponent(s)][EdgeComponent] to be preserved.
     *
     * @param component [EdgeComponent] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun add(component: EdgeComponent) {
        require(issuer.fingerprint == component.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == component.target.fingerprint) { "Target fingerprint mismatch." }

        val certificationsForUserId = _components.getOrPut(component.userId) { mutableListOf() }
        if (certificationsForUserId.isEmpty()) {
            certificationsForUserId.add(component)
            return
        }

        val existing = certificationsForUserId[0]
        // if existing is older than this component
        if (existing.creationTime.before(component.creationTime)) {
            // throw away older certifications
            certificationsForUserId.clear()
        }
        // If this component is newest (or equally old!)
        if (!existing.creationTime.after(component.creationTime)) {
            certificationsForUserId.add(component)
        }
        // else this component is older, so don't add it
    }

    override fun toString(): String {
        return components.map { it.value }.flatten().joinToString("\n")
    }
}