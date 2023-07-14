// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.bouncycastle.util.io.Streams
import org.sequoia_pgp.wot.vectors.BestViaRootVectors
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals

class BestViaRoot : TestCase(BestViaRootVectors()) {

    override val tempFilePrefix: String
        get() = "best-via-root"

    val sq_wot: Pair<String, Array<String>> = "/home/vanitas/Programmierung/sequoia-wot/target/release/sq-wot" to arrayOf()
    val pgpainless_wot: Pair<String, Array<String>> = File(
            File(System.getProperty("user.dir")).parentFile,
            "pgpainless-wot-cli/build/install/pgpainless-wot-cli/bin/pgpainless-wot-cli"
    ).absolutePath to arrayOf("JAVA_HOME=${System.getProperty("java.home")}")

    @Test
    fun sq_wot() {
        execute(sq_wot.first, sq_wot.second)
        execute(pgpainless_wot.first, pgpainless_wot.second)
    }

    override fun execute(executable: String, env: Array<String>) {
        val keyRing = tempKeyRingFile.absolutePath
        val v = vectors as BestViaRootVectors
        val p = Runtime.getRuntime().exec(
                "$executable --keyring=$keyRing -r ${v.alice_fpr} --full authenticate ${v.target_fpr} ${v.target_uid}",
                env)
        val output = p.inputStream.let {
            val bOut = ByteArrayOutputStream()
            Streams.pipeAll(it, bOut)
            bOut.toString()
        }
        Streams.pipeAll(p.errorStream, System.err)
        p.waitFor(5, TimeUnit.SECONDS)
        assertEquals(0, p.exitValue())
        assertEquals(
                """[✓] 2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0 <target@example.org>: fully authenticated (100%)
  ◯ B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB ("<alice@example.org>")
  │   certified the following certificate on 2021-09-27 (expiry: 2026-09-27) as a fully trusted meta-introducer (depth: 10)
  ├ 6A8B9EC7D0A1B297B5D4A7A1C048DFF96601D9BD ("<bob@example.org>")
  │   certified the following certificate on 2021-09-27 (expiry: 2026-09-27) as a fully trusted meta-introducer (depth: 10)
  ├ 77A6F7D4BEE0369F70B249579D2987669F792B35 ("<carol@example.org>")
  │   certified the following binding on 2021-09-27 (expiry: 2026-09-27) as a fully trusted meta-introducer (depth: 10)
  └ 2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0 "<target@example.org>"

""", output)
    }
}