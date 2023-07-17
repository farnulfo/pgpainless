package org.sequoia_pgp.wot.suite

import org.junit.jupiter.api.Named
import org.junit.jupiter.params.provider.Arguments
import org.sequoia_pgp.wot.suite.harness.ExecutableHarness
import org.sequoia_pgp.wot.suite.harness.WotCLIHarness
import org.sequoia_pgp.wot.vectors.ArtifactVectors
import java.io.File
import kotlin.test.assertEquals

/**
 * Test case which allows to query the given [ArtifactVectors] using different WOT implementations.
 *
 * To implement a concrete test case, extend this class and add one or more methods with the following signature:
 * ```
 * @ParameterizedTest
 * @MethodSource("instances")
 * fun exampleTest(callback: ExecutionCallback) {
 *     val arguments = arrayOf("--keyring", keyRingPath(), "--full", "identify", ...)
 *     val expectedOutput = "[✓] 2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0 <target@example.org>: fully authenticated (100%)" +
 *             "..."
 *     assertResultEquals(callback, arguments, expectedOutput, 0)
 * }
 * ```
 */
open class TestCase(val vectors: ArtifactVectors) {

    internal fun keyRingPath(): String =
            vectors.tempKeyRingFile.absolutePath

    fun assertResultEquals(
            callback: ExecutionCallback,
            arguments: Array<String>,
            expectedOutput: String,
            expectedExitCode: Int) {
        val result = callback.execute(vectors, arguments)

        assertEquals(expectedOutput, result.first)
        assertEquals(expectedExitCode, result.second)
    }

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