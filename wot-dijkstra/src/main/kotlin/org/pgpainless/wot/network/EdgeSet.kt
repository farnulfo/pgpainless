// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

/**
 * A [EdgeSet] is a set of [Certifications][Edge] made by the same issuer, on the same
 * target certificate.
 * In some sense, a [EdgeSet] can be considered an edge in the web of trust.
 *
 * @param issuer synopsis of the certificate that issued the [Certifications][Edge]
 * @param target synopsis of the certificate that is targeted by the [Certifications][Edge]
 * @param certifications [Map] keyed by user-ids, whose values are [Lists][List] of
 * [Certifications][Edge] that are calculated over the key user-id. Note, that the key can also be null for
 * [Certifications][Edge] over the targets primary key.
 */
class EdgeSet(
        val issuer: Node,
        val target: Node,
        certifications: Map<String?, List<Edge>>) {

    init {
        certifications.forEach { (_, certifications) ->
            certifications.forEach {
                add(it)
            }
        }
    }

    private val _certifications: MutableMap<String?, MutableList<Edge>> = mutableMapOf()
    val certifications: Map<String?, List<Edge>>
        get() = _certifications.toMutableMap()

    companion object {

        /**
         * Create an empty [EdgeSet].
         *
         * @param issuer the certificate that issued the [Certifications][Edge].
         * @param target the certificate that is targeted by the [Certifications][Edge].
         */
        @JvmStatic
        fun empty(issuer: Node, target: Node): EdgeSet {
            return EdgeSet(issuer, target, HashMap())
        }

        /**
         * Create a [EdgeSet] from a single [Edge].
         *
         * @param edge edge
         */
        @JvmStatic
        fun fromCertification(edge: Edge): EdgeSet {
            val set = empty(edge.issuer, edge.target)
            set.add(edge)
            return set
        }
    }

    /**
     * Merge the given [EdgeSet] into this.
     * This method copies all [Certifications][Edge] from the other [EdgeSet] into [certifications].
     *
     * @param other [EdgeSet] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun merge(other: EdgeSet) {
        if (other == this) {
            return
        }

        require(issuer.fingerprint == other.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == other.target.fingerprint) { "Target fingerprint mismatch." }

        for (userId in other.certifications.keys) {
            for (certification in other.certifications[userId]!!) {
                add(certification)
            }
        }
    }

    /**
     * Add a single [Edge] into this objects [certifications].
     * Adding multiple [Certifications][Edge] for the same datum, but with different creation times results in
     * only the most recent [Edge(s)][Edge] to be preserved.
     *
     * @param edge [Edge] with the same issuer fingerprint and target fingerprint as this object.
     */
    fun add(edge: Edge) {
        require(issuer.fingerprint == edge.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == edge.target.fingerprint) { "Target fingerprint mismatch." }

        val certificationsForUserId = _certifications.getOrPut(edge.userId) { mutableListOf() }
        if (certificationsForUserId.isEmpty()) {
            certificationsForUserId.add(edge)
            return
        }

        val existing = certificationsForUserId[0]
        // if existing is older than this edge
        if (existing.creationTime.before(edge.creationTime)) {
            // throw away older certifications
            certificationsForUserId.clear()
        }
        // If this edge is newest (or equally old!)
        if (!existing.creationTime.after(edge.creationTime)) {
            certificationsForUserId.add(edge)
        }
        // else this edge is older, so don't add it
    }

    override fun toString(): String {
        return certifications.map { it.value }.flatten().joinToString("\n")
    }
}