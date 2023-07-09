// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * An [Edge] comprises a set of signatures ([EdgeComponent]) made by the same issuer, on the same target certificate.
 *
 * @param issuer synopsis of the certificate that issued the [Certifications][EdgeComponent]
 * @param target synopsis of the certificate that is targeted by the [Certifications][EdgeComponent]
 * @param components [Map] keyed by user-ids, whose values are [Lists][List] of
 * [EdgeComponents][EdgeComponent] that are calculated over the key user-id. Note, that the key can also be null for
 * [EdgeComponents][EdgeComponent] over the targets primary key.
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

    private val _certifications: MutableMap<String?, MutableList<EdgeComponent>> = mutableMapOf()
    val components: Map<String?, List<EdgeComponent>>
        get() = _certifications.toMutableMap()

    companion object {

        /**
         * Create an empty [Edge].
         *
         * @param issuer origin of the [Edge].
         * @param target targeted of the [Edge].
         */
        @JvmStatic
        fun empty(issuer: Node, target: Node): Edge {
            return Edge(issuer, target, HashMap())
        }

        /**
         * Create a [Edge] from a single [EdgeComponent].
         *
         * @param edgeComponent edgeComponent
         */
        @JvmStatic
        fun fromCertification(edgeComponent: EdgeComponent): Edge {
            val set = empty(edgeComponent.issuer, edgeComponent.target)
            set.add(edgeComponent)
            return set
        }
    }

    /**
     * Merge the given [Edge] into this.
     * This method copies all [EdgeComponents][EdgeComponent] from the other [Edge] into [components].
     *
     * @param other [Edge] with the same issuer and target as this object.
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
     * @param edgeComponent [EdgeComponent] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun add(edgeComponent: EdgeComponent) {
        require(issuer.fingerprint == edgeComponent.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == edgeComponent.target.fingerprint) { "Target fingerprint mismatch." }

        val certificationsForUserId = _certifications.getOrPut(edgeComponent.userId) { mutableListOf() }
        if (certificationsForUserId.isEmpty()) {
            certificationsForUserId.add(edgeComponent)
            return
        }

        val existing = certificationsForUserId[0]
        // if existing is older than this edgeComponent
        if (existing.creationTime.before(edgeComponent.creationTime)) {
            // throw away older certifications
            certificationsForUserId.clear()
        }
        // If this edgeComponent is newest (or equally old!)
        if (!existing.creationTime.after(edgeComponent.creationTime)) {
            certificationsForUserId.add(edgeComponent)
        }
        // else this edgeComponent is older, so don't add it
    }

    override fun toString(): String {
        return components.map { it.value }.flatten().joinToString("\n")
    }
}