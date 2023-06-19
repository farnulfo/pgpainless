// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import javax.annotation.Nonnull;
import java.util.Date;

public interface ReferenceTime {

    @Nonnull Date getTimestamp();

    static ReferenceTime now() {
        final Date now = new Date();
        return new ReferenceTime() {
            @Override
            @Nonnull
            public Date getTimestamp() {
                return now;
            }
        };
    }

    static ReferenceTime timestamp(@Nonnull Date timestamp) {
        return new ReferenceTime() {
            @Override
            @Nonnull
            public Date getTimestamp() {
                return timestamp;
            }
        };
    }
}
