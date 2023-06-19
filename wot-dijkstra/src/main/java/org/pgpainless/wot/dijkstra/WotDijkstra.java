// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra;

import javax.annotation.Nullable;

public class WotDijkstra<T> extends Dijkstra<T, TrustEdge<T>, Cost.TrustCost> {

    @Override
    @Nullable
    public Path<T, Node<T>, Cost.TrustCost, TrustEdge<T>> findPath(Node<T> to) {
        return null;
    }
}

