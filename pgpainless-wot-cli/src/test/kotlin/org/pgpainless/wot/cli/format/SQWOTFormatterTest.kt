package org.pgpainless.wot.cli.format

import org.junit.jupiter.api.Test
import org.pgpainless.wot.api.AuthenticateAPI
import org.pgpainless.wot.api.Binding
import org.pgpainless.wot.network.*
import org.pgpainless.wot.query.Path
import org.pgpainless.wot.query.Paths
import java.text.SimpleDateFormat
import kotlin.test.assertEquals

class SQWOTFormatterTest {
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd")
    private val formatter = SQWOTFormatter() as Formatter

    private val nodeAlice = Node(fingerprint = Fingerprint("A".repeat(40)),
            userIds = mapOf("Alice <alice@pgpainless.org>" to RevocationState.notRevoked()))
    private val nodeBob = Node(fingerprint = Fingerprint("B".repeat(40)))
    private val nodeCharlie = Node(fingerprint = Fingerprint("C".repeat(40)),
            userIds = mapOf("Charlie <charlie@example.org>" to RevocationState.notRevoked()))

    @Test
    fun `testFormattingOfAuthenticateResult`() {
        val targetAmount = 120
        val binding = Binding(
                nodeAlice.fingerprint,
                "Alice <alice@pgpainless.org>",
                Paths().apply {
                    add(
                            Path(nodeBob, mutableListOf((EdgeComponent(
                                    nodeBob,
                                    nodeAlice,
                                    "Alice <alice@pgpainless.org>",
                                    dateFormat.parse("2023-01-01"),
                                    null,
                                    true,
                                    120,
                                    Depth.auto(10),
                                    RegexSet.wildcard())
                                    )),
                                    Depth.auto(9)),
                            120)
                }
        )
        val result = AuthenticateAPI.Result(binding, targetAmount)
        val output = formatter.format(result)

        assertEquals("""
[✓] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Alice <alice@pgpainless.org>: fully authenticated (100%)
  ◯ BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
  │   certified the following binding on 2023-01-01
  └ AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "Alice <alice@pgpainless.org>"
""".trimStart(), output)
    }
}