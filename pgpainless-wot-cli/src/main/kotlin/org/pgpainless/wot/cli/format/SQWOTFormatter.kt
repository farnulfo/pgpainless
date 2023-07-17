// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.format

import org.pgpainless.wot.api.Binding
import org.pgpainless.wot.network.Depth
import org.pgpainless.wot.network.EdgeComponent
import java.text.SimpleDateFormat

class SQWOTFormatter: Formatter {

    private val dateFormat: SimpleDateFormat = SimpleDateFormat("yyyy-MM-dd")

    /**
     * Format a single binding
     */
    override fun format(binding: Binding, amountMin: Int, amountReference: Int): String {
        val percentage = binding.percentage(amountReference)
        val authLevel = when(binding.paths.amount) {
            in 0..39 -> "not authenticated"
            in 40..119 -> "partially authenticated"
            in 120 .. 239 -> "fully authenticated"
            else -> {if (percentage < 0) "not authenticated" else "doubly authenticated"}
        }
        val checkmark = if(binding.paths.amount >= amountMin) "[✓] " else "[ ] "
        val pathList = binding.paths.paths
        val singlePath = pathList.size == 1
        val indent = " ".repeat(if (singlePath) 2 else 4)

        return buildString {
            // [✓] 7F9116FEA90A5983936C7CFAA027DB2F3E1E118A Paul Schaub <vanitasvitae@fsfe.org>: fully authenticated (100%)
            append(checkmark); appendLine("${binding.fingerprint} ${binding.userId}: $authLevel (${percentage}%)")
            for ((pIndex, path) in pathList.withIndex()) {
                if (!singlePath) {
                    appendLine("  Path #${pIndex + 1} of ${pathList.size}, trust amount ${path.amount}:")
                }
                val originUserId = if (path.root.userIds.isEmpty())
                    ""
                else if (path.root.fingerprint == path.target.fingerprint)
                    " \"${path.root.userIds.keys.first()}\""
                else
                    " (\"${path.root.userIds.keys.first()}\")"
                append(indent); appendLine("◯ ${path.root.fingerprint}$originUserId")
                for ((eIndex, edge) in path.certifications.withIndex()) {
                    val targetUserId = if (edge.userId == null) "" else " \"${edge.userId}\""
                    append(indent); appendLine("│   ${certDegree(edge.trustAmount)}the following " +
                            (if (edge.userId == null) "binding" else "certificate") +
                            " on ${dateFormat.format(edge.creationTime)}" +
                            (if (edge.expirationTime == null) "" else " (expiry: ${dateFormat.format(edge.expirationTime)})") +
                            introducerType(edge)
                    )

                    append(indent); append(if (eIndex != path.certifications.lastIndex) "├ " else "└ ")
                    appendLine("${edge.target.fingerprint}$targetUserId")
                }
                if (pIndex != pathList.lastIndex) {
                    appendLine()
                }
            }
        }
    }

    private fun introducerDegree(amount: Int): String {
        return when (amount) {
            in 1..119 -> "partially"
            else -> if (amount <= 0) "not" else "fully"
        }
    }

    private fun introducerType(edge: EdgeComponent): String {
        return when (edge.trustDepth.value()) {
            0 -> ""
            1 -> " as a ${introducerDegree(edge.trustAmount)} trusted introducer (depth: ${edge.trustDepth.value()})"
            else -> " as a ${introducerDegree(edge.trustAmount)} trusted meta-introducer (depth: ${edge.trustDepth.value()})"
        }

    }

    private fun certDegree(amount: Int): String {
        return when (amount) {
            in 1 .. 119 -> "partially certified (amount: $amount of 120) "
            else -> if (amount <= 0) "did not certify (amount: $amount of 120) " else "certified "
        }
    }
}