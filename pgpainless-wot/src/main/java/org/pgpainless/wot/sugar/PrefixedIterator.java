// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.sugar;

import java.util.Iterator;

/**
 * Returns a new {@link Iterator} with a prepended item.
 * @param <T> item type
 */
public class PrefixedIterator<T> implements Iterator<T> {

    private T prefix;
    private Iterator<T> iterator;

    public PrefixedIterator(T prefix, Iterator<T> iterator) {
        this.prefix = prefix;
        this.iterator = iterator;
    }

    @Override
    public boolean hasNext() {
        return prefix != null || iterator.hasNext();
    }

    @Override
    public T next() {
        if (prefix != null) {
            T t = prefix;
            prefix = null;
            return t;
        }
        return iterator.next();
    }
}
