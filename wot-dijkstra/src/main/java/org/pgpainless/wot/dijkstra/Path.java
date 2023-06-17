package org.pgpainless.wot.dijkstra;

import java.util.Arrays;
import java.util.List;

public class Path<T, N extends Node<T>, C extends Cost, E extends Edge<T, C>> {

    private final N from;
    private final N to;

    private final List<E> edges;

    public Path(N from, N to, List<E> edges) {
        this.from = from;
        this.to = to;
        this.edges = edges;
    }

    public Node<T> getFrom() {
        return from;
    }

    public Node<T> getTo() {
        return to;
    }

    public List<E> getEdges() {
        return edges;
    }

    @Override
    public String toString() {
        return Arrays.toString(getEdges().toArray());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Path)) {
            return false;
        }
        Path<?, ?, ?, ?> other = (Path<?, ?, ?, ?>) obj;
        return getFrom().equals(other.getFrom())
                && getTo().equals(other.getTo())
                && getEdges().equals(other.getEdges());
    }

    @Override
    public int hashCode() {
        return getFrom().hashCode()
                + 13 * getTo().hashCode()
                + 31 * getEdges().hashCode();
    }
}
