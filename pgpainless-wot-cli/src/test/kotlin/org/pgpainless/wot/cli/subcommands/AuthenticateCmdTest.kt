// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.junit.jupiter.api.Test
import org.pgpainless.wot.api.AuthenticateAPI
import org.pgpainless.wot.api.Binding
import org.pgpainless.wot.cli.format.SQWOTFormatter
import org.pgpainless.wot.network.*
import org.pgpainless.wot.query.Path
import org.pgpainless.wot.query.Paths
import java.text.SimpleDateFormat
import kotlin.test.assertEquals

class AuthenticateCmdTest {

    @Test
    fun testFormatting() {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd")
        val paths = Paths()
        val neal = Node(
                Fingerprint("F7173B3C7C685CD9ECC4191B74E445BA0E15C957"),
                null,
                RevocationState.notRevoked(),
                mapOf(
                        Pair("Neal H. Walfield (Code Signing Key) <neal@pep.foundation>", RevocationState.notRevoked())
                )
        )
        val justus = Node(
                Fingerprint("CBCD8F030588653EEDD7E2659B7DD433F254904A"),
                null,
                RevocationState.notRevoked(),
                mapOf(
                        Pair("Justus Winter <justus@sequoia-pgp.org>", RevocationState.notRevoked())
                )
        )
        val edgeComponent = EdgeComponent(
                neal,
                justus,
                "Justus Winter <justus@sequoia-pgp.org>",
                dateFormat.parse("2022-02-04"),
                null,
                true,
                120,
                Depth.limited(0),
                RegexSet.wildcard())
        paths.add(Path(neal, mutableListOf(edgeComponent), Depth.auto(0)), 120)
        val testResult = AuthenticateAPI.Result(Binding(
                Fingerprint("CBCD8F030588653EEDD7E2659B7DD433F254904A"),
                "Justus Winter <justus@sequoia-pgp.org>",
                paths),
                120, )

        val formatted = SQWOTFormatter().format(testResult)
        assertEquals(buildString {
            appendLine("[✓] CBCD8F030588653EEDD7E2659B7DD433F254904A Justus Winter <justus@sequoia-pgp.org>: fully authenticated (100%)")
            appendLine("  ◯ F7173B3C7C685CD9ECC4191B74E445BA0E15C957 (\"Neal H. Walfield (Code Signing Key) <neal@pep.foundation>\")")
            appendLine("  │   certified the following binding on 2022-02-04")
            appendLine("  └ CBCD8F030588653EEDD7E2659B7DD433F254904A \"Justus Winter <justus@sequoia-pgp.org>\"")
        }, formatted)
    }
}