// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.bouncycastle.util.io.Streams
import org.sequoia_pgp.wot.vectors.ArtifactVectors
import java.io.File
import java.nio.file.Files
import kotlin.io.path.outputStream

abstract class TestCase(val vectors: ArtifactVectors) {

    abstract val tempFilePrefix: String
    val tempFileSuffix = ".pgp"

    val tempKeyRingFile: File
        get() {
            val path = Files.createTempFile(tempFilePrefix, tempFileSuffix)

            val outputStream = path.outputStream()
            Streams.pipeAll(vectors.keyRingInputStream(), outputStream)
            outputStream.close()

            val file = path.toFile()
            file.deleteOnExit()
            return file
        }

    abstract fun execute(executable: String, envp: Array<String>)
}