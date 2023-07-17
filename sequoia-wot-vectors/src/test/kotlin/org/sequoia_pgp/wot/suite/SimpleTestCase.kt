// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.sequoia_pgp.wot.vectors.ArtifactVectors

/**
 * Simple test case, which tests a single WOT query invocation and compares the output to the expected result.
 */
abstract class SimpleTestCase(vectors: ArtifactVectors): TestCase(vectors)  {

    @ParameterizedTest
    @MethodSource("instances")
    fun execute(callback: ExecutionCallback) {
        assertResultEquals(callback, arguments(), expectedOutput().first, expectedOutput().second)
    }

    abstract fun arguments(): Array<String>

    abstract fun expectedOutput(): Pair<String, Int>
}