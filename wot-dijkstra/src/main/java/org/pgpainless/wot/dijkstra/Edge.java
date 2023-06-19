// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra;

public abstract class Edge<T, C extends Cost> implements Comparable<C> {

    protected final Node<T> from;
    protected final Node<T> to;
    protected final C cost;

    public Edge(Node<T> from, Node<T> to, C cost) {
        this.from = from;
        this.to = to;
        this.cost = cost;
    }

    public Node<T> getFrom() {
        return from;
    }

    public Node<T> getTo() {
        return to;
    }

    public C getCost() {
        return cost;
    }
}
