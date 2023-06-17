package org.pgpainless.wot.dijkstra;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ShortestPathDijkstra<T> extends Dijkstra<T, SimpleEdge<T>, Cost.SimpleCost> {

    private final Node<T> root;
    private final Graph<T, Node<T>, SimpleEdge<T>, Cost.SimpleCost> graph;
    private final List<Node<T>> queue = new ArrayList<>();

    private final Map<Node<T>, Double> distances = new HashMap<>();
    private final Map<Node<T>, SimpleEdge<T>> precursors = new HashMap<>();

    public ShortestPathDijkstra(Graph<T, Node<T>, SimpleEdge<T>, Cost.SimpleCost> graph, Node<T> root) {
        // INITIALIZE
        this.graph = graph;
        this.root = root;
        for (Node<T> node : graph.getNodes()) {
            // dist[v] := infinity
            distances.put(node, Double.MAX_VALUE);

            // precursor[v] := null
            precursors.put(node, null);
        }
        // dist[root] := 0
        distances.put(root, 0d);

        // Q := set of all nodes in graph
        queue.addAll(graph.getNodes());

        while (!queue.isEmpty()) {
            Node<T> closest = closest();
            queue.remove(closest);

            for (SimpleEdge<T> edge : graph.getEdges()) {
                if (!closest.equals(edge.getFrom())) {
                    // Skip non-neighbors
                    continue;
                }

                if (queue.contains(edge.getTo())) {
                    distUpdate(closest, edge.getTo());
                }
            }
        }
    }

    private Node<T> closest() {
        Double minDist = Double.MAX_VALUE;
        int index = 0;
        Double dist;
        for (int i = 0; i < queue.size(); i++) {
            if ((dist = distances.get(queue.get(i))) <= minDist) {
                index = i;
                minDist = dist;
            }
        }
        return queue.get(index);
    }

    private void distUpdate(Node<T> from, Node<T> to) {
        SimpleEdge<T> edge = getEdgeBetween(from, to);
        if (edge == null) {
            // No direct path
            return;
        }

        Double distance = distances.get(from) + edge.getCost().getWeight();
        if (distance < distances.get(to)) {
            distances.put(to, distance);
            precursors.put(to, edge);
        }
    }

    private SimpleEdge<T> getEdgeBetween(Node<T> from, Node<T> to) {
        for (SimpleEdge<T> edge : graph.getEdges()) {
            if (!from.equals(edge.getFrom())) {
                continue;
            }

            if (to.equals(edge.getTo())) {
                return edge;
            }
        }
        return null;
    }

    @Override
    @Nullable
    public Path<T, Node<T>, Cost.SimpleCost, SimpleEdge<T>> findPath(Node<T> to) {
        List<SimpleEdge<T>> pathEdges = new ArrayList<>();
        Node<T> waypoint = to;

        SimpleEdge<T> edge;
        while ((edge = precursors.get(waypoint)) != null) {
            waypoint = precursors.get(waypoint).getFrom();
            pathEdges.add(0, edge);
        }

        if (pathEdges.isEmpty()) {
            return null;
        }

        return new Path<>(root, to, pathEdges);
    }
}
