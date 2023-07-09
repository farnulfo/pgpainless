// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKeyRing

import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.wot.dijkstra.sq.Edge
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.Network
import org.pgpainless.wot.testfixtures.TestCertificateStores
import org.pgpainless.wot.testfixtures.WotTestVectors
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.Test

class WebOfTrustTest {

    private val fooBankCa = fingerprintOf(WotTestVectors.freshFooBankCaCert)
    private val fooBankEmployee = fingerprintOf(WotTestVectors.freshFooBankEmployeeCert)
    private val fooBankAdmin = fingerprintOf(WotTestVectors.freshFooBankAdminCert)
    private val barBankCa = fingerprintOf(WotTestVectors.freshBarBankCaCert)
    private val barBankEmployee = fingerprintOf(WotTestVectors.freshBarBankEmployeeCert)

    private fun fingerprintOf(cert: PGPPublicKeyRing): Fingerprint {
        return Fingerprint(OpenPgpFingerprint.of(cert).toString())
    }

    @Test
    fun testWithTwoNodesAndOneDelegation() {
        val certD = TestCertificateStores.oneDelegationGraph()
        val network = WebOfTrust(certD).buildNetwork()

        assertEquals(2, network.nodes.size)
        assertHasEdge(network, fooBankAdmin, barBankCa)
        assertHasReverseEdge(network, fooBankAdmin, barBankCa)

        assertHasNoEdge(network, barBankCa, fooBankAdmin)
        assertHasNoReverseEdge(network, barBankCa, fooBankAdmin)
    }

    @Test
    fun testWithCrossSignedCertificates() {
        val certD = TestCertificateStores.disconnectedGraph()
        val network = WebOfTrust(certD).buildNetwork()

        assertEquals(5, network.nodes.size)
        assertTrue {
            listOf(fooBankCa, fooBankEmployee, fooBankAdmin, barBankCa, barBankEmployee).all {
                network.nodes.containsKey(it)
            }
        }

        val fooBankCaEdges = network.edges[fooBankCa]!!
        assertEquals(2, fooBankCaEdges.size)

        val fbc2fbe = getEdgeFromTo(network, fooBankCa, fooBankEmployee)
        assertNotNull(fbc2fbe)

        val fbc2fba = getEdgeFromTo(network, fooBankCa, fooBankAdmin)
        assertNotNull(fbc2fba)

        assertHasIssuerAndTarget(fbc2fbe, fooBankCa, fooBankEmployee)
        assertHasIssuerAndTarget(fbc2fba, fooBankCa, fooBankAdmin)

        assertHasEdge(network, barBankCa, barBankEmployee)
        assertHasReverseEdge(network, barBankCa, barBankEmployee)

        assertHasNoEdge(network, fooBankCa, barBankCa)
        assertHasNoReverseEdge(network, fooBankCa, barBankCa)
    }

    @Test
    fun testWotCreationOfEmptyCertificates() {
        val certD = TestCertificateStores.emptyGraph()
        val network = WebOfTrust(certD).buildNetwork()

        assertTrue { network.nodes.isEmpty() }
        assertTrue { network.edges.isEmpty() }
        assertTrue { network.reverseEdges.isEmpty() }
    }

    @Test
    fun testWotWithAnomaly() {
        val store = TestCertificateStores.anomalyGraph()
        val network = WebOfTrust(store).buildNetwork()

        assertEquals(1, network.nodes.size)
    }


    private fun assertHasIssuerAndTarget(
            certifications: Edge,
            issuer: Fingerprint,
            target: Fingerprint) {
        assertEquals(issuer, certifications.issuer.fingerprint)
        assertEquals(target, certifications.target.fingerprint)
    }

    private fun assertHasEdge(network: Network, issuer: Fingerprint, target: Fingerprint) {
        assertNotNull(getEdgeFromTo(network, issuer, target), "Expected edge from $issuer to $target but got none.")
    }

    private fun assertHasReverseEdge(network: Network, issuer: Fingerprint, target: Fingerprint) {
        assertNotNull(getReverseEdgeFromTo(network, issuer, target), "Expected reverse edge to $target from $issuer but got none.")
    }

    private fun assertHasNoEdge(network: Network, issuer: Fingerprint, target: Fingerprint) {
        val edge = getEdgeFromTo(network, issuer, target)
        assertNull(edge, "Expected no edge from $issuer to $target but got $edge")
    }

    private fun assertHasNoReverseEdge(network: Network, issuer: Fingerprint, target: Fingerprint) {
        val reverseEdge = getReverseEdgeFromTo(network, issuer, target)
        assertNull(reverseEdge, "Expected no reverse edge on $target from $issuer but got $reverseEdge")
    }

    private fun getEdgeFromTo(network: Network, issuer: Fingerprint, target: Fingerprint): Edge? {
        val edges = network.edges[issuer] ?: return null
        return edges.find { target == it.target.fingerprint }
    }

    private fun getReverseEdgeFromTo(network: Network, issuer: Fingerprint, target: Fingerprint): Edge? {
        val revEdges = network.reverseEdges[target] ?: return null
        return revEdges.find { issuer == it.issuer.fingerprint }
    }
}