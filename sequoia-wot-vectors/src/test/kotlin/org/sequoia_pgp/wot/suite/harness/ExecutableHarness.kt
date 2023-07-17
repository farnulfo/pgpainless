// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite.harness

import org.bouncycastle.util.io.Streams
import org.sequoia_pgp.wot.suite.ExecutionCallback
import org.sequoia_pgp.wot.vectors.ArtifactVectors
import java.io.ByteArrayOutputStream

/**
 * Harness for a WOT executable (e.g. sq-wot).
 * @param executable full path to the executable file
 * @param environment set of environment variables in the format 'key=value'
 */
class ExecutableHarness(val executable: String, val environment: Array<String>): Harness() {

    override fun runner(): ExecutionCallback {
        return object: ExecutionCallback {

            override fun execute(vectors: ArtifactVectors, arguments: Array<String>): Pair<String, Int> {
                val command = arrayOf(executable).plus(arguments)
                val p = Runtime.getRuntime().exec(command, environment)
                val output = p.inputStream.let {
                    val bOut = ByteArrayOutputStream()
                    Streams.pipeAll(it, bOut)
                    bOut.toString()
                }
                Streams.pipeAll(p.errorStream, System.err)
                val exit = p.waitFor()
                return output to exit
            }
        }
    }


}