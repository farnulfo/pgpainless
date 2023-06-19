// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class Optional<T> {

    private final T item;

    public static <T> Optional<T> empty() {
        return new Optional<>();
    }

    public static <T> Optional<T> just(@Nonnull T item) {
        return new Optional<>(item);
    }

    public static <T> Optional<T> maybe(@Nullable T item) {
        return item == null ? empty() : just(item);
    }

    private Optional() {
        this.item = null;
    }

    private Optional(@Nonnull T item) {
        this.item = item;
    }

    public boolean isEmpty() {
        return item == null;
    }

    public boolean isPresent() {
        return item != null;
    }

    public @Nonnull T get() {
        if (item == null) {
            throw new NullPointerException("Item is null.");
        }
        return item;
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof Optional)) {
            return false;
        }

        Optional other = (Optional) obj;
        if (isEmpty() && other.isEmpty()) {
            return true;
        }

        if (isPresent() && isPresent()) {
            return get().equals(other.get());
        }

        return false;
    }
}
