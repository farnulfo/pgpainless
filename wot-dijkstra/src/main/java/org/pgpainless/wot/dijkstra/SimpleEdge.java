package org.pgpainless.wot.dijkstra;

public class SimpleEdge<T> extends Edge<T, Cost.SimpleCost> {

    public SimpleEdge(Node<T> from, Node<T> to, Double edgeWeight) {
        super(from, to, new Cost.SimpleCost(edgeWeight));
    }

    @Override
    public String toString() {
        return getFrom().toString() + " " + getCost() + "> " + getTo().toString();
    }

    @Override
    public int compareTo(Cost.SimpleCost o) {
        return Double.compare(getCost().getWeight(), o.getWeight());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SimpleEdge)) {
            return false;
        }
        SimpleEdge<?> other = (SimpleEdge<?>) obj;

        return getFrom().equals(other.getFrom())
                && getTo().equals(other.getTo())
                && getCost().equals(other.getCost());
    }

    @Override
    public int hashCode() {
        return getFrom().hashCode() + 13 * getTo().hashCode() + 17 * getCost().hashCode();
    }
}
