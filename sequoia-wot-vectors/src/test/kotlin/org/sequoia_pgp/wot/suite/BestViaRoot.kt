// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite

import org.sequoia_pgp.wot.vectors.BestViaRootVectors

class BestViaRoot : SimpleTestCase(BestViaRootVectors()) {

    override fun arguments(): Array<String> {
        val v = vectors as BestViaRootVectors
        return arrayOf("--keyring", keyRingPath(), "-r", v.aliceFpr.toString(), "--full", "authenticate", v.targetFpr.toString(), v.targetUid)
    }

    override fun expectedOutput(): Pair<String, Int> {
        return """[✓] 2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0 <target@example.org>: fully authenticated (100%)
  ◯ B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB ("<alice@example.org>")
  │   certified the following certificate on 2021-09-27 (expiry: 2026-09-27) as a fully trusted meta-introducer (depth: 10)
  ├ 6A8B9EC7D0A1B297B5D4A7A1C048DFF96601D9BD ("<bob@example.org>")
  │   certified the following certificate on 2021-09-27 (expiry: 2026-09-27) as a fully trusted meta-introducer (depth: 10)
  ├ 77A6F7D4BEE0369F70B249579D2987669F792B35 ("<carol@example.org>")
  │   certified the following binding on 2021-09-27 (expiry: 2026-09-27) as a fully trusted meta-introducer (depth: 10)
  └ 2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0 "<target@example.org>"

""" to 0
    }
}