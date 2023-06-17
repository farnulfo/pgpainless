package org.pgpainless.wot.dijkstra;

public class Node<T> {

    private final T item;

    public Node(T item) {
        this.item = item;
    }

    private T getItem() {
        return item;
    }

    @Override
    public String toString() {
        return "(" + getItem().toString() + ")";
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Node)) {
            return false;
        }

        Node<?> other = (Node<?>) obj;
        return getItem().equals(other.getItem());
    }

    @Override
    public int hashCode() {
        return getItem().hashCode();
    }
}
