// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.junit.jupiter.api.Named
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.sequoia_pgp.wot.suite.harness.ExecutableHarness
import org.sequoia_pgp.wot.suite.harness.WotCLIHarness
import org.sequoia_pgp.wot.vectors.ArtifactVectors
import java.io.File
import kotlin.test.assertEquals

abstract class TestCase(val vectors: ArtifactVectors) {

    interface ExecutionCallback {
        fun execute(vectors: ArtifactVectors, arguments: Array<String>): Pair<String, Int>
    }

    @ParameterizedTest
    @MethodSource("instances")
    fun execute(callback: ExecutionCallback) {
        val arguments = arguments()
        val expectedOutput = expectedOutput()

        val result = callback.execute(vectors, arguments)
        assertEquals(expectedOutput.first, result.first)
        assertEquals(expectedOutput.second, result.second)
    }

    abstract fun arguments(): Array<String>

    abstract fun expectedOutput(): Pair<String, Int>

    internal fun keyRingPath(): String =
            vectors.tempKeyRingFile.absolutePath

    companion object {
        @JvmStatic
        fun instances(): List<Arguments> {
            return buildList {
                // pgpainless-wot-cli
                add(Arguments.of(Named.of("pgpainless-wot-cli", WotCLIHarness().runner())))

                // sq-wot, if environment variable "SQ_WOT" points to sq-wot executable
                val sqWotExe = System.getenv("SQ_WOT")
                if (sqWotExe != null && File(sqWotExe).let { it.exists() && it.isFile }) {
                    add(Arguments.of(Named.of("sq-wot", ExecutableHarness(sqWotExe, arrayOf()).runner())))
                }
            }
        }
    }
}