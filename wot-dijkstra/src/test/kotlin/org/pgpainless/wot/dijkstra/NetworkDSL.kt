// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.pgpainless.wot.dijkstra.sq.*
import java.util.*

/**
 * Tons of useful DSL for [Network]-related testing.
 */
interface NetworkDSL {

    /**
     * Create [Node] from [String] fingerprint.
     */
    fun CertSynopsis(fingerprint: String): Node =
            Node(Fingerprint(fingerprint), null, RevocationState.notRevoked(), mapOf())

    /**
     * Create [Node] from [String] fingerprint and non-revoked [userId].
     */
    fun CertSynopsis(fingerprint: String, userId: String): Node = Node(
            Fingerprint(fingerprint), null, RevocationState.notRevoked(), mapOf(userId to RevocationState.notRevoked()))

    fun CertSynopsis(original: Node, userId: String): Node = Node(
            original.fingerprint, original.expirationTime, original.revocationState, original.userIds.plus(userId to RevocationState.notRevoked())
    )

    /**
     * Create [Edge] from two [Node] nodes.
     */
    fun Certification(issuer: Node, target: Node): Edge =
            Edge(issuer, target, null, Date())

    /**
     * Create [Edge] from two [Node] nodes and a target [userId].
     */
    fun Certification(issuer: Node, target: Node, userId: String): Edge =
            Edge(issuer, target, userId, Date())

    fun Certification(issuer: Node, target: Node, amount: Int, depth: Depth): Edge =
            Edge(issuer, target, null, Date(), null, true, amount, depth, RegexSet.wildcard())

    /**
     * Add a single [Node] built from a [String] fingerprint to the builder.
     */
    fun Network.Builder.addNode(fingerprint: String): Network.Builder {
        return addNode(CertSynopsis(fingerprint))
    }

    /**
     * Add a single [Node] built from a [String] fingerprint and [userId] to the builder.
     */
    fun Network.Builder.addNode(fingerprint: String, userId: String): Network.Builder {
        return addNode(CertSynopsis(fingerprint, userId))
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
        return addEdge(Certification(issuerNode, targetNode))
    }

    /**
     * Add an edge for [userId] between the [Node] with fingerprint [issuer] and
     * the [Node] with fingerprint [target].
     * If either the issuer or target node doesn't exist, throw an [IllegalArgumentException].
     */
    fun Network.Builder.addEdge(issuer: String, target: String, userId: String): Network.Builder {
        val issuerNode = nodes[Fingerprint(issuer)]!!
        val targetNode = nodes[Fingerprint(target)]!!
        return addEdge(Certification(issuerNode, targetNode, userId))
    }

    /**
     * Add an edge between the issuer and target node. If either of them doesn't exist, add
     * a new node for them to the builder.
     */
    fun Network.Builder.buildEdge(issuer: String, target: String): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { CertSynopsis(issuer) }
        val targetNode = nodes.getOrPut(Fingerprint(target)) { CertSynopsis(target) }
        return addEdge(Certification(issuerNode, targetNode))
    }

    /**
     * Add an edge for [userId] between the issuer and the target node. If either of them doesn't
     * exist, add a new node.
     * If the target node exists, but doesn't carry the [userId], replace it with a copy with
     * the [userId] inserted.
     */
    fun Network.Builder.buildEdge(issuer: String, target: String, userId: String): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { CertSynopsis(issuer)}
        val targetNode = CertSynopsis(nodes.getOrPut(Fingerprint(target)) { CertSynopsis(target, userId) }, userId)
        return addEdge(Certification(issuerNode, targetNode, userId))
    }

    fun Network.Builder.buildEdge(issuer: String, target: String, amount: Int, depth: Int): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { CertSynopsis(issuer) }
        val targetNode = nodes.getOrPut(Fingerprint(target)) { CertSynopsis(target) }
        return addEdge(Edge(issuerNode, targetNode, null, Date(), null, true, amount, Depth.auto(depth), RegexSet.wildcard()))
    }

    fun Network.Builder.buildEdge(issuer: String, target: String, amount: Int, depth: Int, regexSet: RegexSet): Network.Builder {
        val issuerNode = nodes.getOrPut(Fingerprint(issuer)) { CertSynopsis(issuer) }
        val targetNode = nodes.getOrPut(Fingerprint(target)) { CertSynopsis(target) }
        return addEdge(Edge(issuerNode, targetNode, null, Date(), null, true, amount, Depth.auto(depth), regexSet))
    }

    /**
     * Set the reference time of the builder to now.
     */
    fun Network.Builder.now(): Network.Builder {
        return setReferenceTime(ReferenceTime.now())
    }

    fun Network.getEdgesFor(issuer: Fingerprint, target: Fingerprint): EdgeSet? {
        return edgeSet[issuer]?.find { it.target.fingerprint == target }
    }

    fun Network.getEdgesFor(issuer: String, target: String): EdgeSet? {
        return getEdgesFor(Fingerprint(issuer), Fingerprint(target))
    }

    fun Network.getEdgeFor(issuer: Fingerprint, target: Fingerprint): List<Edge>? {
        return getEdgeFor(issuer, target, null)
    }

    fun Network.getEdgeFor(issuer: Fingerprint, target: Fingerprint, userId: String?): List<Edge>? {
        return getEdgesFor(issuer, target)?.certifications?.get(userId)
    }

    fun Network.getEdgeFor(issuer: String, target: String): List<Edge>? {
        return getEdgeFor(issuer, target, null)
    }

    fun Network.getEdgeFor(issuer: String, target: String, userId: String?): List<Edge>? {
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