// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*

interface ReferenceTime {

    val timestamp: Date

    companion object {
        @JvmStatic
        fun now(): ReferenceTime {
            val now = Date()
            return object: ReferenceTime {
                override val timestamp: Date
                    get() = now
            }
        }

        @JvmStatic
        fun timestamp(stamp: Date): ReferenceTime {
            return object: ReferenceTime {
                override val timestamp: Date
                    get() = stamp
            }
        }
    }
}