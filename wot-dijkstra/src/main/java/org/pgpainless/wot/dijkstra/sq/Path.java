package org.pgpainless.wot.dijkstra.sq;

import java.util.ArrayList;
import java.util.List;

public class Path {

    private CertSynopsis root;
    private List<Certification> edges;
    private Depth residualDepth;

    public Path(CertSynopsis root) {
        this.root = root;
        this.edges = new ArrayList<>();
        this.residualDepth = Depth.unconstrained();
    }

    public CertSynopsis getRoot() {
        return root;
    }

    public CertSynopsis getTarget() {
        if (edges.isEmpty()) {
            return getRoot();
        } else {
            return edges.get(edges.size() - 1).getTarget();
        }
    }

    public List<CertSynopsis> getCertificates() {
        List<CertSynopsis> certs = new ArrayList<>();
        certs.add(getRoot());
        for (Certification edge : edges) {
            certs.add(edge.getTarget());
        }
        return certs;
    }

    public int getLength() {
        return edges.size() + 1;
    }

    public List<Certification> getCertifications() {
        return new ArrayList<>(edges);
    }

    public Depth getResidualDepth() {
        return residualDepth;
    }

    public int getAmount() {
        if (edges.isEmpty()) {
            return 120;
        }
        int min = 255;
        for (Certification edge : edges) {
            min = Math.min(min, edge.getTrustAmount());
        }
        return min;
    }

    public void append(Certification certification) {
        if (!getTarget().getFingerprint().equals(certification.getIssuer().getFingerprint())) {
            throw new IllegalArgumentException("Cannot append certification to path: Path's tail is not issuer of the certification.");
        }

        if (!residualDepth.isUnconstrained() && residualDepth.getLimit().get() == 0) {
            throw new IllegalArgumentException("Not enough depth.");
        }

        boolean cyclic = getRoot().getFingerprint().equals(certification.getTarget().getFingerprint());
        for (int i = 0; i < edges.size() && !cyclic; i++) {
            Certification edge = edges.get(i);

            if (edge.getTarget().getFingerprint().equals(certification.getTarget().getFingerprint())) {
                if (i == edges.size() - 1) {
                    cyclic = edge.getUserId().equals(certification.getUserId());
                } else {
                    cyclic = true;
                }
            }
        }
        if (cyclic) {
            throw new IllegalArgumentException("Adding the certification to the path would create a cycle.");
        }

        residualDepth = certification.getTrustDepth().min(residualDepth.decrease(1));
        edges.add(certification);
    }
}
