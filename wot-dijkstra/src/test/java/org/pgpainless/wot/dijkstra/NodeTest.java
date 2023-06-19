// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class NodeTest {

    @Test
    public void equalsTest() {
        Node<String> n1 = new Node<>("foo");
        Node<String> n1_ = new Node<>("foo");
        Node<String> n2 = new Node<>("bar");

        assertEquals(n1, n1_);
        assertEquals(n1, n1);
        assertNotEquals(n1, n2);

        Map<Node<String>, String> map = new HashMap<>();
        map.put(n1, "foo");
        map.put(n2, "bar");

        assertEquals("foo", map.get(n1));
        assertEquals("bar", map.get(n2));
        assertEquals("foo", map.get(n1_));
    }
}
