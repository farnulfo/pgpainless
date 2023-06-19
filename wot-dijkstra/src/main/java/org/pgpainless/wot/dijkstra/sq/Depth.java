// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import org.pgpainless.wot.dijkstra.IntegerUtils;

import javax.annotation.Nonnull;

public final class Depth implements Comparable<Depth> {

    private final Optional<Integer> depth;

    private Depth(Optional<Integer> depth) {
        this.depth = depth;
        if (!isUnconstrained() && (getLimit().get() < 0 || getLimit().get() > 255)) {
            throw new IllegalArgumentException("Depth must be a value between 0 and 255");
        }
    }

    public static Depth unconstrained() {
        return new Depth(Optional.empty());
    }

    public static Depth limited(int depth) {
        return new Depth(Optional.just(depth));
    }

    public static Depth auto(int depth) {
        return depth == 255 ? unconstrained() : limited(depth);
    }

    public Optional<Integer> getLimit() {
        return depth;
    }

    public boolean isUnconstrained() {
        return getLimit().isEmpty();
    }

    public Depth decrease(int value) {
        if (isUnconstrained()) {
            return unconstrained();
        }
        if (getLimit().get() >= value) {
            return limited(getLimit().get() - value);
        }
        throw new IllegalArgumentException("Depth cannot be decreased.");
    }

    @Override
    public int compareTo(@Nonnull Depth o) {
        if (isUnconstrained()) {
            if (o.isUnconstrained()) {
                return 0;
            } else {
                return 1;
            }
        } else {
            if (o.isUnconstrained()) {
                return -1;
            } else {
                return IntegerUtils.compare(getLimit().get(), o.getLimit().get());
            }
        }
    }

    @Override
    public String toString() {
        return isUnconstrained() ? "unconstrained" : getLimit().get().toString();
    }

    public Depth min(Depth other) {
        if (compareTo(other) <= 0) {
            return this;
        } else {
            return other;
        }
    }

}
