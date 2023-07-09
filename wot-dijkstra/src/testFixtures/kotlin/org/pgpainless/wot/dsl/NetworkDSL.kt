// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dsl

import org.pgpainless.wot.network.*
import java.util.*

/**
 * Tons of useful DSL for [Network]-related testing.
 */
interface NetworkDSL {

    /**
     * Create [Node] from [String] fingerprint.
     */
    fun Node(fingerprint: String): Node =
            Node(Fingerprint(fingerprint), null, RevocationState.notRevoked(), mapOf())

    /**
     * Create [Node] from [String] fingerprint and non-revoked [userId].
     */
    fun Node(fingerprint: String, userId: String): Node = Node(
            Fingerprint(fingerprint), null, RevocationState.notRevoked(), mapOf(userId to RevocationState.notRevoked()))

    fun Node(original: Node, userId: String): Node = Node(
            original.fingerprint, original.expirationTime, original.revocationState, original.userIds.plus(userId to RevocationState.notRevoked())
    )

    /**
     * Create [EdgeComponent] from two [Node] nodes.
     */
    fun EdgeComponent(issuer: Node, target: Node): EdgeComponent =
            EdgeComponent(issuer, target, null, Date())

    /**
     * Create [EdgeComponent] from two [Node] nodes and a target [userId].
     */
    fun EdgeComponent(issuer: Node, target: Node, userId: String): EdgeComponent =
            EdgeComponent(issuer, target, userId, Date())

    fun EdgeComponent(issuer: Node, target: Node, amount: Int, depth: Depth): EdgeComponent =
            EdgeComponent(issuer, target, null, Date(), null, true, amount, depth, RegexSet.wildcard())


    /**
     * Construct a [EdgeComponent] with default values. The result is non-expiring, will be exportable and has a
     * trust amount of 120, a depth of 0 and a wildcard regex.
     *
     * @param issuer synopsis of the certificate that issued the [EdgeComponent]
     * @param target synopsis of the certificate that is target of this [EdgeComponent]
     * @param targetUserId optional user-id. If this is null, the [EdgeComponent] is made over the primary key of the target.
     * @param creationTime creation time of the [EdgeComponent]
     */
    fun EdgeComponent(issuer: Node, target: Node, targetUserId: String? = null, creationTime: Date): EdgeComponent =
            EdgeComponent(issuer, target, targetUserId, creationTime, null, true, 120, Depth.limited(0), RegexSet.wildcard())


    /**
     * Add a single [Node] built from a [String] fingerprint to the builder.
     */
    fun Network.Builder.addNode(fingerprint: String): Network.Builder {
        return addNode(Node(fingerprint))
    }

    /**
     * Add a single [Node] built from a [String] fingerprint and [userId] to the builder.
     */
    fun Network.Builder.addNode(fingerprint: String, userId: String): Network.Builder {
        return addNode(Node(fingerprint, userId))
    }

    /**
     * Add multiple [Node] nodes built from [String] fingerprints to the builder.
     */
    fun Network.Builder.addNodes(vararg fingerprints: String) {
        for (fingerprint in fingerprints) {
            addNode(fingerprint)
        }
    }

    /**
     * Add an edge between the [Node] with fingerprint [issuer] and
     * the [Node] with fingerprint [target].
     * If either the issuer or target node doesn't exist, throw an [IllegalArgumentException].
     */
    fun Network.Builder.addEdge(issuer: String, target: String): Network.Builder {
        val issuerNode = nodes[Fingerprint(issuer)]!!
        val targetNode = nodes[Fingerprint(target)]!!
        return addEdge(EdgeComponent(issuerNode, targetNode))
    }

    /**
     * Add an edge for [userId] between the [Node] with fingerprint [issuer] and
     * the [Node] with fingerprint [target].
     * If either the issuer or target node doesn't exist, throw an [IllegalArgumentException].
     */
    fun Network.Builder.addEdge(issuer: String, target: String, userId: String): Network.Builder {
        val issuerNode = nodes[Fingerprint(issuer)]!!
        val targetNode = nodes[Fingerprint(target)]!!
        return addEdge(EdgeComponent(issuerNode, targetNode, userId))
    }

    /**
     * Add an edge between the issuer and target node. If either of them doesn't exist, add
     * a new node for them to the builder.
     */
    fun Network.Builder.buildEdge(issuer: String, target: String): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { Node(issuer) }
        val targetNode = nodes.getOrPut(Fingerprint(target)) { Node(target) }
        return addEdge(EdgeComponent(issuerNode, targetNode))
    }

    /**
     * Add an edge for [userId] between the issuer and the target node. If either of them doesn't
     * exist, add a new node.
     * If the target node exists, but doesn't carry the [userId], replace it with a copy with
     * the [userId] inserted.
     */
    fun Network.Builder.buildEdge(issuer: String, target: String, userId: String): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { Node(issuer)}
        val targetNode = Node(nodes.getOrPut(Fingerprint(target)) { Node(target, userId) }, userId)
        return addEdge(EdgeComponent(issuerNode, targetNode, userId))
    }

    fun Network.Builder.buildEdge(issuer: String, target: String, amount: Int, depth: Int): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { Node(issuer) }
        val targetNode = nodes.getOrPut(Fingerprint(target)) { Node(target) }
        return addEdge(EdgeComponent(issuerNode, targetNode, null, Date(), null, true, amount, Depth.auto(depth), RegexSet.wildcard()))
    }

    fun Network.Builder.buildEdge(issuer: String, target: String, amount: Int, depth: Int, regexSet: RegexSet): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { Node(issuer) }
        val targetNode = nodes.getOrPut(Fingerprint(target)) { Node(target) }
        return addEdge(EdgeComponent(issuerNode, targetNode, null, Date(), null, true, amount, Depth.auto(depth), regexSet))
    }

    /**
     * Set the reference time of the builder to now.
     */
    fun Network.Builder.now(): Network.Builder {
        return setReferenceTime(ReferenceTime.now())
    }

    fun Network.getEdgesFor(issuer: Fingerprint, target: Fingerprint): Edge? {
        return edges[issuer]?.find { it.target.fingerprint == target }
    }

    fun Network.getEdgesFor(issuer: String, target: String): Edge? {
        return getEdgesFor(Fingerprint(issuer), Fingerprint(target))
    }

    fun Network.getEdgeFor(issuer: Fingerprint, target: Fingerprint): List<EdgeComponent>? {
        return getEdgeFor(issuer, target, null)
    }

    fun Network.getEdgeFor(issuer: Fingerprint, target: Fingerprint, userId: String?): List<EdgeComponent>? {
        return getEdgesFor(issuer, target)?.components?.get(userId)
    }

    fun Network.getEdgeFor(issuer: String, target: String): List<EdgeComponent>? {
        return getEdgeFor(issuer, target, null)
    }

    fun Network.getEdgeFor(issuer: String, target: String, userId: String?): List<EdgeComponent>? {
        return getEdgeFor(Fingerprint(issuer), Fingerprint(target), userId)
    }

    fun Date.plusMillis(millis: Long): Date {
        return Date(time + millis)
    }

    fun Date.plusSeconds(seconds: Long): Date {
        return plusMillis(1000L * seconds)
    }

    fun Date.plusMinutes(minutes: Long): Date {
        return plusSeconds(60 * minutes)
    }

    fun Date.plusHours(hours: Long): Date {
        return plusMinutes(60 * hours)
    }

    fun Date.plusDays(days: Long): Date {
        return plusHours(24 * days)
    }

    fun domainRegex(domain: String): RegexSet {
        return RegexSet.fromExpression("<[^>]+[@.]" + domain.replace(".", "\\.") + ">$")
    }

    /**
     * Lambda with Receiver.
     *
     * @see <a href="https://betterprogramming.pub/test-data-creation-using-the-power-of-kotlin-dsl-9526a1fad05b"/>
     */
    fun buildNetwork(builderAction: Network.Builder.() -> Unit): Network {
        val builder = Network.builder()
        builder.builderAction()
        return builder.build()
    }
}