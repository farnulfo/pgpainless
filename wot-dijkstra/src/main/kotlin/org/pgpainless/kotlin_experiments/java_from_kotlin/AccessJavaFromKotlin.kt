// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.kotlin_experiments.java_from_kotlin

import org.pgpainless.kotlin_experiments.AJavaClass

/**
 * Verify that we can access Java code from the Kotlin codebase.
 * Accesses [AJavaClass] and executes [AJavaClass.doSomething].
 */
fun main(args: Array<String>) {
    AccessJavaFromKotlin().run()
}

class AccessJavaFromKotlin {

    fun run() {
        val java = AJavaClass()
        java.doSomething()
    }
}