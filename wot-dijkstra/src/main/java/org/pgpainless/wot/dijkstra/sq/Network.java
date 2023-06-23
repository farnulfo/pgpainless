// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

import org.pgpainless.key.OpenPgpFingerprint;

public class Network {

    private final Map<OpenPgpFingerprint, CertSynopsis> nodes;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> edges;
    private final Map<OpenPgpFingerprint, List<CertificationSet>> reverseEdges;
    private final ReferenceTime referenceTime;

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

    public Map<OpenPgpFingerprint, CertSynopsis> getNodes() {
        return new HashMap<>(nodes);
    }

    public Map<OpenPgpFingerprint, List<CertificationSet>> getEdges() {
        return new HashMap<>(edges);
    }

    public Map<OpenPgpFingerprint, List<CertificationSet>> getReverseEdges() {
        return new HashMap<>(reverseEdges);
    }

    public ReferenceTime getReferenceTime() {
        return referenceTime;
    }

}
