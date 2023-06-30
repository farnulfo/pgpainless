// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.wot.dijkstra.sq.CertificationSet;
import org.pgpainless.wot.dijkstra.sq.Fingerprint;
import org.pgpainless.wot.dijkstra.sq.Network;
import org.pgpainless.wot.testfixtures.TestCertificateStores;
import org.pgpainless.wot.testfixtures.WotTestVectors;
import pgp.cert_d.PGPCertificateDirectory;
import pgp.certificate_store.exception.BadDataException;

public class WebOfTrustTest {

    Fingerprint fooBankCa = fingerprintOf(WotTestVectors.getTestVectors().getFreshFooBankCaCert());
    Fingerprint fooBankEmployee = fingerprintOf(WotTestVectors.getTestVectors().getFreshFooBankEmployeeCert());
    Fingerprint fooBankAdmin = fingerprintOf(WotTestVectors.getTestVectors().getFreshFooBankAdminCert());
    Fingerprint barBankCa = fingerprintOf(WotTestVectors.getTestVectors().getFreshBarBankCaCert());
    Fingerprint barBankEmployee = fingerprintOf(WotTestVectors.getTestVectors().getFreshBarBankEmployeeCert());

    public WebOfTrustTest() throws IOException {

    }

    private static Fingerprint fingerprintOf(PGPPublicKeyRing cert) {
        return new Fingerprint(OpenPgpFingerprint.of(cert).toString());
    }

    @Test
    public void testWithTwoNodesAndOneDelegation() throws BadDataException, IOException, InterruptedException {
        PGPCertificateDirectory certD = TestCertificateStores.oneDelegationGraph();
        WebOfTrust wot = new WebOfTrust(certD);
        wot.initialize();
        Network network = wot.getNetwork();

        assertEquals(2, network.getNodes().size());

        assertHasEdge(network, fooBankAdmin, barBankCa);
        assertHasReverseEdge(network, fooBankAdmin, barBankCa);

        assertHasNoEdge(network, barBankCa, fooBankAdmin);
        assertHasNoReverseEdge(network, barBankCa, fooBankAdmin);
    }

    @Test
    public void testWithCrossSignedCertificates()
            throws BadDataException, IOException, InterruptedException {
        PGPCertificateDirectory certD = TestCertificateStores.disconnectedGraph();
        WebOfTrust wot = new WebOfTrust(certD);
        wot.initialize();
        Network network = wot.getNetwork();

        assertEquals(5, network.getNodes().size());
        assertTrue(network.getNodes().containsKey(fooBankCa));
        assertTrue(network.getNodes().containsKey(fooBankEmployee));
        assertTrue(network.getNodes().containsKey(fooBankAdmin));
        assertTrue(network.getNodes().containsKey(barBankCa));
        assertTrue(network.getNodes().containsKey(barBankEmployee));

        // Exemplary edge
        List<CertificationSet> fooBankCaEdges = network.getEdges().get(fooBankCa);
        assertEquals(2, fooBankCaEdges.size());

        CertificationSet fbc2fbe = getEdgeFromTo(network, fooBankCa, fooBankEmployee);
        assertNotNull(fbc2fbe);
        CertificationSet fbc2fba = getEdgeFromTo(network, fooBankCa, fooBankAdmin);
        assertNotNull(fbc2fba);

        assertHasIssuerAndTarget(fbc2fba, fooBankCa, fooBankAdmin);
        assertHasIssuerAndTarget(fbc2fbe, fooBankCa, fooBankEmployee);

        assertHasEdge(network, barBankCa, barBankEmployee);
        assertHasReverseEdge(network, barBankCa, barBankEmployee);

        assertHasNoEdge(network, fooBankCa, barBankCa);
        assertHasNoReverseEdge(network, fooBankCa, barBankCa);

        // CHECKSTYLE:OFF
        System.out.println(wot);
        // CHECKSTYLE:ON
    }

    private void assertHasIssuerAndTarget(CertificationSet certifications, Fingerprint issuer, Fingerprint target) {
        assertEquals(issuer, certifications.getIssuer().getFingerprint());
        assertEquals(target, certifications.getTarget().getFingerprint());
    }

    private void assertHasEdge(Network network, Fingerprint issuer, Fingerprint target) {
        assertNotNull(getEdgeFromTo(network, issuer, target), "Expected edge from " + issuer + " to " + target + " but got none.");
    }

    private void assertHasReverseEdge(Network network, Fingerprint issuer, Fingerprint target) {
        assertNotNull(getReverseEdgeFromTo(network, issuer, target), "Expected reverse edge to " + target + " from " + issuer + " but got none.");
    }

    private void assertHasNoEdge(Network network, Fingerprint issuer, Fingerprint target) {
        CertificationSet edge = getEdgeFromTo(network, issuer, target);
        assertNull(edge, "Expected no edge from " + issuer + " to " + target + " but got " + edge);
    }

    private void assertHasNoReverseEdge(Network network, Fingerprint issuer, Fingerprint target) {
        CertificationSet reverseEdge = getReverseEdgeFromTo(network, issuer, target);
        assertNull(reverseEdge, "Expected no reverse edge on " + target + " from " + issuer + " but got " + reverseEdge);
    }

    private CertificationSet getEdgeFromTo(Network network, Fingerprint issuer, Fingerprint target) {
        List<CertificationSet> edges = network.getEdges().get(issuer);
        if (edges == null) {
            return null;
        }

        for (CertificationSet certifications : edges) {
            if (target.equals(certifications.getTarget().getFingerprint())) {
                return certifications;
            }
        }
        return null;
    }

    private CertificationSet getReverseEdgeFromTo(Network network, Fingerprint issuer, Fingerprint target) {
        List<CertificationSet> revEdges = network.getReverseEdges().get(target);
        if (revEdges == null) {
            return null;
        }

        for (CertificationSet certifications : revEdges) {
            if (issuer.equals(certifications.getIssuer().getFingerprint())) {
                return certifications;
            }
        }
        return null;
    }

    @Test
    public void testWotCreationOfEmptyCertificates() {
        PGPCertificateDirectory certD = TestCertificateStores.emptyGraph();
        WebOfTrust wot = new WebOfTrust(certD);
        wot.initialize();
        Network network = wot.getNetwork();

        assertTrue(network.getNodes().isEmpty());
        assertTrue(network.getEdges().isEmpty());
        assertTrue(network.getReverseEdges().isEmpty());
    }

    @Test
    public void testWotWithAnomaly() throws BadDataException, IOException, InterruptedException {
        PGPCertificateDirectory store = TestCertificateStores.anomalyGraph();
        WebOfTrust wot = new WebOfTrust(store);
        wot.initialize();
        Network network = wot.getNetwork();

        assertEquals(1, network.getNodes().size());
    }
}
