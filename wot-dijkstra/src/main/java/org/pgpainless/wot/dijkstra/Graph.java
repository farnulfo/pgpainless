// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra;

import java.util.Collection;

public class Graph<T, N extends Node<T>, E extends Edge<T, C>, C extends Cost> {

    private final Collection<N> nodes;
    private final Collection<E> edges;

    public Graph(Collection<N> nodes, Collection<E> edges) {
        this.nodes = nodes;
        this.edges = edges;
    }

    public Collection<N> getNodes() {
        return nodes;
    }

    public Collection<E> getEdges() {
        return edges;
    }
}
