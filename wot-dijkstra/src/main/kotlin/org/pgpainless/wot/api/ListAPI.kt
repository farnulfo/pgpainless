// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

interface ListAPI {

    fun list(): Result

    data class Result(val bindings: List<Binding>, val targetAmount: Int)
}
