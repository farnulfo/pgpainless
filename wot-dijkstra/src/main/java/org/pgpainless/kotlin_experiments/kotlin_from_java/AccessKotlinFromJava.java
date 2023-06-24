// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.kotlin_experiments.kotlin_from_java;

import org.pgpainless.kotlin_experiments.AKotlinClass;

/**
 * Example class to verify that we can access Kotlin classes from our Java code \o/.
 * Accesses {@link AKotlinClass} and executes {@link AKotlinClass#printToStdout()}.
 */
public class AccessKotlinFromJava {

    public static void main(String[] args) {
        // from src/kotlin/.../
        AKotlinClass kotlin = new AKotlinClass();
        // CHECKSTYLE:OFF
        kotlin.printToStdout();
        // CHECKSTYLE:ON
    }
}
