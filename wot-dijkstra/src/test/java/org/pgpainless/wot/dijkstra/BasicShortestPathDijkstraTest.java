// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class BasicShortestPathDijkstraTest {

    /**
     * Generate a test graph from a string definition.
     * The definition might look like this:
     * <pre>
     *     Alice
     *     Bob -1> Charlie
     *     Charlie -4> Dieter -1> Alice
     *     Dieter -2> Charlie
     * </pre>
     * @param definition definition
     * @return graph
     */
    private Graph<String, Node<String>, SimpleEdge<String>, Cost.SimpleCost> generate(String definition) {
        Set<Node<String>> nodes = new HashSet<>();
        Set<SimpleEdge<String>> edges = new HashSet<>();
        String[] lines = definition.split("\n");
        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }

            String[] fromTo = line.split(" -\\d+> ");
            if (fromTo.length == 1) {
                // Unconnected node
                nodes.add(new Node<>(fromTo[0]));
                continue;
            }

            int searchOffset = 0;
            for (int i = 0; i < fromTo.length - 1; i++) {
                Node<String> from = new Node<>(fromTo[i]);
                nodes.add(from);
                searchOffset += fromTo[i].length() + " -".length();
                int costStop = line.indexOf("> ", searchOffset);
                String costString = line.substring(searchOffset, costStop);
                Double cost = Double.parseDouble(costString);
                searchOffset += costString.length() + "> ".length();
                Node<String> to = new Node<>(fromTo[i + 1]);
                nodes.add(to);

                edges.add(new SimpleEdge<>(from, to, cost));
            }
        }

        return new Graph<>(nodes, edges);
    }

    private Path<String, Node<String>, Cost.SimpleCost, SimpleEdge<String>> path(String definition) {
        definition = definition.trim();
        String[] fromTo = definition.split(" -\\d+> ");
        if (fromTo.length == 1) {
            // Unconnected node
            Node<String> node = new Node<>(fromTo[0]);
            return new Path<>(node, node, Collections.singletonList(new SimpleEdge<>(node, node, 0d)));
        }

        Node<String> start = null;
        Node<String> end = null;
        List<SimpleEdge<String>> edges = new ArrayList<>();
        int searchOffset = 0;
        for (int i = 0; i < fromTo.length - 1; i++) {
            Node<String> from = new Node<>(fromTo[i]);
            if (start == null) {
                start = from;
            }
            searchOffset += fromTo[i].length() + " -".length();
            int costStop = definition.indexOf("> ", searchOffset);
            String costString = definition.substring(searchOffset, costStop);
            Double cost = Double.parseDouble(costString);
            searchOffset += costString.length() + "> ".length();
            Node<String> to = new Node<>(fromTo[i + 1]);
            edges.add(new SimpleEdge<>(from, to, cost));
            end = to;
        }

        Path<String, Node<String>, Cost.SimpleCost, SimpleEdge<String>> path = new Path<>(start, end, edges);
        return path;
    }

    @Test
    public void exampleGraphTest() {
        Graph<String, Node<String>, SimpleEdge<String>, Cost.SimpleCost> g = generate(
                "Alice\n" +
                        "Bob -1> Charlie\n" +
                        "Bob -3> Dieter -1> Marlene\n" +
                        "Dieter -1> Alice\n" +
                        "Mallory\n");

        Set<Node<String>> expectedNodes = new HashSet<>();
        expectedNodes.add(new Node<>("Alice"));
        expectedNodes.add(new Node<>("Bob"));
        expectedNodes.add(new Node<>("Charlie"));
        expectedNodes.add(new Node<>("Dieter"));
        expectedNodes.add(new Node<>("Marlene"));
        expectedNodes.add(new Node<>("Mallory"));

        assertEquals(expectedNodes, g.getNodes());

        Set<SimpleEdge<String>> expectedEdges = new HashSet<>();
        expectedEdges.add(new SimpleEdge<>(new Node<>("Bob"), new Node<>("Charlie"), 1d));
        expectedEdges.add(new SimpleEdge<>(new Node<>("Bob"), new Node<>("Dieter"), 3d));
        expectedEdges.add(new SimpleEdge<>(new Node<>("Dieter"), new Node<>("Marlene"), 1d));
        expectedEdges.add(new SimpleEdge<>(new Node<>("Dieter"), new Node<>("Alice"), 1d));

        assertEquals(g.getEdges(), expectedEdges);
    }

    @Test
    public void emptyNetworkTest() {
        Graph<String, Node<String>, SimpleEdge<String>, Cost.SimpleCost> graph = generate("");

        Node<String> root = new Node<>("root");
        Node<String> target = new Node<>("target");
        ShortestPathDijkstra<String> dijkstra = new ShortestPathDijkstra<>(graph, root);
        Path<String, Node<String>, Cost.SimpleCost, SimpleEdge<String>> path = dijkstra.findPath(target);

        assertNull(path);
    }

    @Test
    public void pathFindingTest() {
        Graph<String, Node<String>, SimpleEdge<String>, Cost.SimpleCost> graph = generate(
                "Pablo\n" +
                        "Root -2> Alice -3> Alexandra\n" +
                        "Root -1> Karlos -1> Alexandra\n" +
                        "Karlos -2> Malte -4> Sven");

        ShortestPathDijkstra<String> dijkstra = new ShortestPathDijkstra<>(graph, new Node<>("Root"));
        assertEquals(path("Root -1> Karlos -2> Malte -4> Sven"), dijkstra.findPath(new Node<>("Sven")));
        assertEquals(path("Root -1> Karlos"), dijkstra.findPath(new Node<>("Karlos")));
        assertEquals(path("Root -1> Karlos -1> Alexandra"), dijkstra.findPath(new Node<>("Alexandra")));

        dijkstra = new ShortestPathDijkstra<>(graph, new Node<>("Karlos"));
        assertEquals(path("Karlos -2> Malte -4> Sven"), dijkstra.findPath(new Node<>("Sven")));
    }
}
