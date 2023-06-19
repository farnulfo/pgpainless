// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra;

public final class IntegerUtils {

    private IntegerUtils() {

    }

    /**
     * Backported method from Java 8.
     *
     * @param x x
     * @param y y
     * @return result of comparison
     */
    public static int compare(int x, int y) {
        // noinspection UseCompareMethod
        return x < y ? -1 : (x == y ? 0 : 1);
    }
}
