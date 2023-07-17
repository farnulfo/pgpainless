// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite.harness

import org.pgpainless.wot.cli.WotCLI
import org.sequoia_pgp.wot.suite.ExecutionCallback
import org.sequoia_pgp.wot.vectors.ArtifactVectors
import java.io.ByteArrayOutputStream
import java.io.PrintStream

/**
 * Harness for the [WotCLI] class.
 */
class WotCLIHarness: Harness() {

    override fun runner(): ExecutionCallback {
        return object: ExecutionCallback {

            override fun execute(vectors: ArtifactVectors, arguments: Array<String>): Pair<String, Int> {
                val origStdout = System.out

                val bOut = ByteArrayOutputStream()
                System.setOut(PrintStream(bOut))

                val exitCode = WotCLI.execute(arguments)

                System.setOut(origStdout)
                return bOut.toString() to exitCode
            }

        }
    }
}