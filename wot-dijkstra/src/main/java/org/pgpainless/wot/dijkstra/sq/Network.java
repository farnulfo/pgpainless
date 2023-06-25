// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

import org.pgpainless.key.OpenPgpFingerprint;

/**
 * A network consists of nodes, and edges between them.
 * For the Web of Trust, nodes consist of {@link CertSynopsis CertSynopses}, while the edges between the nodes are
 * {@link CertificationSet CertificationSets}.
 * Edges can hereby be accessed in two ways:
 * <ul>
 *     <li>{@link #getEdges()} returns a {@link Map} keyed by the {@link OpenPgpFingerprint fingerprint} of an issuer,
 *     whose values are {@link List Lists} containing all edges originating from the issuer.</li>
 *     <li>{@link #getReverseEdges()} on the other hand returns a {@link Map} keyed by the
 *     {@link OpenPgpFingerprint fingerprint} of a target, whose value are {@link List Lists} containing all edges
 *     pointing to the target.</li>
 * </ul>
 */
public class Network {

    private final Map<OpenPgpFingerprint, CertSynopsis> nodes;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> edges;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges;
    private final ReferenceTime referenceTime;

    /**
     * Create a {@link Network} from a set of nodes, edges, reversed edges and a reference time.
     *
     * @param nodes map containing all nodes of the network, keyed by their fingerprints
     * @param edges map containing all edges of the network, keyed by the fingerprint of the issuer
     * @param reverseEdges map containing all reversed edges of the network, keyed by the fingerprint of the target
     * @param referenceTime reference time
     */
    public Network(Map<OpenPgpFingerprint, CertSynopsis> nodes,
                   Map<OpenPgpFingerprint, List<CertificationSet>> edges,
                   Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges,
                   ReferenceTime referenceTime) {
        this.nodes = nodes;
        this.edges = edges;
        this.reverseEdges = reverseEdges;
        this.referenceTime = referenceTime;
    }

    /**
     * Create an empty {@link Network}.
     *
     * @param referenceTime reference time for evaluation
     * @return network
     */
    public static Network empty(@Nonnull ReferenceTime referenceTime) {
        return new Network(
                new HashMap<>(),
                new HashMap<>(),
                new HashMap<>(),
                referenceTime);
    }

    /**
     * Return all nodes ({@link CertSynopsis}) of the {@link Network}, indexed by their
     * {@link OpenPgpFingerprint fingerprints}.
     *
     * @return nodes of the network
     */
    public Map<OpenPgpFingerprint, CertSynopsis> getNodes() {
        return new HashMap<>(nodes);
    }

    /**
     * Return all edges of the {@link Network}, indexed by the {@link OpenPgpFingerprint fingerprint} of the issuer.
     * An edge consists of a {@link CertificationSet} containing all signatures made by the issuer on the target.
     *
     * @return map of edges
     */
    public Map<OpenPgpFingerprint, List<CertificationSet>> getEdges() {
        return new HashMap<>(edges);
    }

    /**
     * Return all reversed edges of the {@link Network}, indexed by the {@link OpenPgpFingerprint fingerprint} of the target.
     *
     * @return map of reversed edges
     */
    public Map<OpenPgpFingerprint, List<CertificationSet>> getReverseEdges() {
        return new HashMap<>(reverseEdges);
    }

    /**
     * Return the {@link ReferenceTime} which was used when creating the {@link Network}.
     *
     * @return reference time
     */
    public ReferenceTime getReferenceTime() {
        return referenceTime;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("Network with " + getNodes().size() + " nodes, " + getEdges().size() + " edges:\n");
        for (OpenPgpFingerprint issuer : getNodes().keySet()) {
            for (CertificationSet edge : getReverseEdges().get(issuer)) {
                sb.append(edge);
            }
        }
        return sb.toString();
    }
}
