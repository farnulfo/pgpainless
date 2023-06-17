package org.pgpainless.wot.dijkstra;

import javax.annotation.Nonnull;

public class TrustEdge<T> extends Edge<T, Cost.TrustCost> {

    public TrustEdge(Node<T> from, Node<T> to, Cost.TrustCost cost) {
        super(from, to, cost);
    }

    @Override
    public int compareTo(@Nonnull Cost.TrustCost o) {
        int depthCompare = Double.compare(cost.getDepth(), o.getDepth());
        if (depthCompare != 0) {
            return - depthCompare;
        }
        return Double.compare(cost.getAmount(), o.getAmount());
    }
}
