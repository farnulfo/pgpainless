// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.query.Path
import org.pgpainless.wot.query.Paths
import java.text.SimpleDateFormat

data class Binding(val fingerprint: Fingerprint, val userId: String, val paths: Paths) {
    /**
     * Percentage of authentication. 100% means fully authenticated binding.
     */
    fun percentage(targetAmount: Int): Int {
        return paths.amount * 100 / targetAmount
    }

    fun toConsoleOut(targetAmount: Int, dateFormat: SimpleDateFormat): String {
        return buildString {
            val percentage = percentage(targetAmount)
            val authLevel = when (paths.amount) {
                in 0..39 -> "not authenticated"
                in 40..119 -> "partially authenticated"
                in 120 .. 239 -> "fully authenticated"
                else -> {if (percentage < 0) "not authenticated" else "doubly authenticated"}
            }
            append(if (percentage >= 100) "[✓] " else "[ ] ")
            appendLine("$fingerprint $userId: $authLevel (${percentage(targetAmount)}%)")
            for ((pIndex, path: Path) in paths.paths.withIndex()) {
                appendLine("  Path #${pIndex + 1} of ${paths.paths.size}, trust amount ${path.amount}:")
                for ((cIndex, certification) in path.certifications.withIndex()) {
                    val issuerUserId = certification.issuer.userIds.keys.firstOrNull()?.let { " (\"$it\")" } ?: ""
                    when (cIndex) {
                        0 -> {
                            appendLine("    ◯ ${certification.issuer.fingerprint}$issuerUserId")
                        }
                        else -> {
                            appendLine("    ├ ${certification.issuer.fingerprint}$issuerUserId")
                        }
                    }
                    appendLine("    │   certified the following binding on ${dateFormat.format(certification.creationTime)}")
                }
                appendLine("    └ $fingerprint \"$userId\"")
            }
        }
    }
}