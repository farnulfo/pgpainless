package org.pgpainless.wot.cli.subcommands

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.api.AuthenticateAPI
import org.pgpainless.wot.dijkstra.sq.*
import java.text.SimpleDateFormat
import kotlin.test.assertEquals

class AuthenticateCmdTest {

    @Test
    fun testFormatting() {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd")
        val cmd = AuthenticateCmd()
        val paths = Paths()
        val neal = CertSynopsis(
                Fingerprint("F7173B3C7C685CD9ECC4191B74E445BA0E15C957"),
                null,
                RevocationState.notRevoked(),
                mapOf(
                        Pair("Neal H. Walfield (Code Signing Key) <neal@pep.foundation>", RevocationState.notRevoked())
                )
        )
        val justus = CertSynopsis(
                Fingerprint("CBCD8F030588653EEDD7E2659B7DD433F254904A"),
                null,
                RevocationState.notRevoked(),
                mapOf(
                        Pair("Justus Winter <justus@sequoia-pgp.org>", RevocationState.notRevoked())
                )
        )
        val certification = Certification(
                neal,
                justus,
                "Justus Winter <justus@sequoia-pgp.org>",
                dateFormat.parse("2022-02-04"),
                null,
                true,
                120,
                Depth.limited(0),
                RegexSet.wildcard())
        paths.add(Path(neal, mutableListOf(certification), Depth.auto(0)), 120)
        val testResult = AuthenticateAPI.Result(
                Fingerprint("CBCD8F030588653EEDD7E2659B7DD433F254904A"),
                "Justus Winter <justus@sequoia-pgp.org>",
                120,
                paths)

        val formatted = cmd.formatResult(testResult)
        assertEquals(buildString {
            append("[✓] CBCD8F030588653EEDD7E2659B7DD433F254904A Justus Winter <justus@sequoia-pgp.org>: fully authenticated (100%)\n")
            append("  Path #1 of 1, trust amount 120:\n")
            append("    ◯ F7173B3C7C685CD9ECC4191B74E445BA0E15C957 (\"Neal H. Walfield (Code Signing Key) <neal@pep.foundation>\")\n")
            append("    │   certified the following binding on 2022-02-04\n")
            append("    └ CBCD8F030588653EEDD7E2659B7DD433F254904A \"Justus Winter <justus@sequoia-pgp.org>\"\n")
        }, formatted)
    }
}