// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.regex.Pattern

/**
 * Set of regular expressions.
 */
data class RegexSet(val regexStrings: Set<String>) {

    companion object {

        /**
         * Create a [RegexSet] from the given [List] of RegEx strings.
         */
        @JvmStatic
        fun fromExpressionList(regexList: List<String>): RegexSet {
            return RegexSet(regexList.toSet())
        }

        /**
         * Create a [RegexSet] from a single RegEx string.
         */
        @JvmStatic
        fun fromExpression(regex: String): RegexSet {
            return fromExpressionList(listOf(regex))
        }

        /**
         * Create a wildcard RegEx (empty list of RegEx strings).
         */
        @JvmStatic
        fun wildcard(): RegexSet {
            return fromExpressionList(listOf())
        }
    }

    /**
     * Return true if the given [string] matches the [RegexSet].
     * That is if at least one RegEx in the set matches the [string], or if the set represents a wildcard.
     */
    fun matches(string: String): Boolean {
        if (regexStrings.isEmpty()) {
            return true
        }

        for (regex in regexStrings) {
            val matcher = Pattern.compile(regex).matcher(string)
            if (matcher.find()) {
                return true
            }
        }
        return false
    }
}