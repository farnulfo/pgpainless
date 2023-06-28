// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.regex.Pattern

data class RegexSet(val regexStrings: Set<String>) {

    companion object {
        @JvmStatic
        fun fromExpressionList(regexList: List<String>): RegexSet {
            return RegexSet(regexList.toSet())
        }

        @JvmStatic
        fun fromExpression(regex: String): RegexSet {
            return fromExpressionList(listOf(regex))
        }

        @JvmStatic
        fun wildcard(): RegexSet {
            return fromExpressionList(listOf())
        }
    }

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