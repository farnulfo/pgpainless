// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq.api

import org.pgpainless.wot.dijkstra.sq.Fingerprint

interface PathAPI {

    fun path(arguments: Arguments): Result

    data class Arguments(val rootFingerprint: Fingerprint, val pathFingerprints: List<Fingerprint>, val userId: String)

    interface Result {

        fun isSuccess(): Boolean

        class Success: Result {
            override fun isSuccess(): Boolean {
                return true
            }
        }

        data class Failure(val information: List<String>): Result {
            override fun isSuccess(): Boolean {
                return false
            }
        }
    }
}
