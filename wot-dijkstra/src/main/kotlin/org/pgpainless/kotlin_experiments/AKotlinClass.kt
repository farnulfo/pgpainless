// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.kotlin_experiments

/**
 * Some Kotlin class that is used by AccessKotlinFromJava in src/main/java/...
 */
class AKotlinClass {

    fun printToStdout() {
        // CHECKSTYLE:OFF
        println("'Hello, World' from Kotlin!")
        // CHECKSTYLE:ON
    }
}