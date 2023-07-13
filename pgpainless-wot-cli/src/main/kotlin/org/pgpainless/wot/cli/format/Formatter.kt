// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.format

import org.pgpainless.wot.api.*

interface Formatter {

    /**
     * Format a binding.
     * @param binding binding to format
     * @param amountMin minimum trust amount to accept the binding
     * @param amountReference reference value to compare the amount against to calculate percentage
     */
    fun format(binding: Binding, amountMin: Int = 120, amountReference: Int = 120): String

    fun format(authenticateResult: AuthenticateAPI.Result): String {
        return buildString {
            append(format(authenticateResult.binding, authenticateResult.targetAmount))
            if (!authenticateResult.acceptable) {
                appendLine()
                append("Could not authenticate any paths.")
            }
        }
    }

    fun format(identifyResult: IdentifyAPI.Result): String {
        return buildString {
            identifyResult.bindings.forEach {
                appendLine(format(it, identifyResult.targetAmount))
            }
            if (!identifyResult.acceptable) {
                appendLine("Could not authenticate any paths.")
            }
        }
    }

    fun format(listResult: ListAPI.Result): String {
        return buildString {
            listResult.bindings.forEach {
                appendLine(format(it, listResult.targetAmount))
            }
        }
    }

    fun format(lookupResult: LookupAPI.Result): String {
        return buildString {
            lookupResult.bindings.forEach {
                appendLine(format(it, lookupResult.targetAmount))
            }
            if (!lookupResult.acceptable) {
                appendLine("Could not authenticate any paths.")
            }
        }
    }
}