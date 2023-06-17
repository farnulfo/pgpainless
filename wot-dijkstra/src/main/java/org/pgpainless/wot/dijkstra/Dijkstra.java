package org.pgpainless.wot.dijkstra;

import javax.annotation.Nullable;

public abstract class Dijkstra<T, E extends Edge<T, C>, C extends Cost> {
    @Nullable
    public abstract Path<T, Node<T>, C, E> findPath(Node<T> to);
}
