// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.util.ArrayList;
import java.util.List;

public class Paths {

    private final List<Item> paths = new ArrayList<>();

    public List<Item> getPaths() {
        return new ArrayList<>(paths);
    }

    public void add(Path path, int amount) {
        if (amount <= path.getAmount()) {
            throw new AssertionError();
        }
        this.paths.add(new Item(path, amount));
    }

    public int getAmount() {
        int sum = 0;
        for (Item item : paths) {
            sum += item.amount;
        }
        return sum;
    }

    public static class Item {
        private final Path path;
        private final int amount;

        public Item(Path path, int amount) {
            this.path = path;
            this.amount = amount;
        }

        public Path getPath() {
            return path;
        }

        public int getAmount() {
            return amount;
        }
    }
}
