// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.dijkstra.sq.Paths

interface LookupAPI {

    fun lookup(arguments: Arguments): Result

    data class Arguments(val userId: String, val email: Boolean = false)

    data class Result(val paths: Paths)
}
