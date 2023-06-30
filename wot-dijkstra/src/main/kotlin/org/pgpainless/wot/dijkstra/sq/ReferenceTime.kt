// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*

/**
 * Reference time for Web of Trust calculations.
 */
interface ReferenceTime {

    /**
     * Timestamp as [Date].
     */
    val timestamp: Date

    companion object {

        /**
         * Create a [ReferenceTime] with a timestamp that corresponds to the current time.
         */
        @JvmStatic
        fun now(): ReferenceTime {
            return timestamp(Date())
        }

        /**
         * Create a [ReferenceTime] from the given [stamp] timestamp.
         */
        @JvmStatic
        fun timestamp(stamp: Date): ReferenceTime {
            return object: ReferenceTime {
                override val timestamp: Date
                    get() = stamp
            }
        }
    }
}