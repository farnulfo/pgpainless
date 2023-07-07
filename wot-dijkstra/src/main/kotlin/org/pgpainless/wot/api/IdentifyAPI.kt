// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.Paths

interface IdentifyAPI {

    fun identify(arguments: Arguments): Result

    data class Arguments(val fingerprint: Fingerprint)

    data class Result(val paths: Paths)
}
