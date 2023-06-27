// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.sugar;

import java.util.Iterator;

/**
 * Because an {@link Iterator} is not {@link Iterable} ¯\_(ツ)_/¯.
 * @param <T> item
 */
public final class IterableIterator<T> implements Iterable<T> {

    private final Iterator<T> iterator;

    public IterableIterator(Iterator<T> iterator) {
        this.iterator = iterator;
    }

    @Override
    public Iterator<T> iterator() {
        return iterator;
    }
}
