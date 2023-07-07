// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

/**
 * Enum listing possible output formats.
 */
enum class Format(private val displayName: String) {
    humanReadable("human-readable"),
    dot("dot")
    ;

    override fun toString(): String = displayName

    companion object {
        @JvmStatic
        fun fromString(displayName: String): Format {
            for (format in Format.values()) {
                if (format.displayName == displayName) {
                    return format
                }
            }
            throw NoSuchElementException("Invalid displayName $displayName")
        }
    }
}