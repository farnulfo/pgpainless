// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.query.Paths

interface IdentifyAPI {

    fun identify(arguments: Arguments): Result

    data class Arguments(val fingerprint: Fingerprint)

    data class Result(val paths: Map<String, Paths>, val target: Node?, val targetAmount: Int) {
        fun percentage(userId: String): Int? {
            if (paths[userId] == null) {
                return null
            }
            return paths[userId]!!.amount * 100 / targetAmount
        }
    }
}
