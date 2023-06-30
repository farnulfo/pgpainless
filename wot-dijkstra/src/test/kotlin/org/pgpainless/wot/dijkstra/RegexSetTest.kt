package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dijkstra.sq.RegexSet
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RegexSetTest {

    private val exampleComRegex = "<[^>]+[@.]example\\.com>\$"
    private val pgpainlessOrgRegex = "<[^>]+[@.]pgpainless\\.org>\$"

    @Test
    fun testWildcard() {
        val wildcard = RegexSet.wildcard()
        assertTrue { wildcard.matches("Alice <alice@pgpainless.org>") }
        assertTrue { wildcard.matches("Bob <bob@example.com>") }
    }

    @Test
    fun testDomainRegex() {
        val exampleCom = RegexSet.fromExpression(exampleComRegex)
        assertTrue { exampleCom.matches("Bob <bob@example.com>") }
        assertTrue { exampleCom.matches("<admin@example.com>") }
        assertFalse { exampleCom.matches("Spoofed <bob@examp1e.com>") }
        assertFalse { exampleCom.matches("Alice <alice@pgpainless.org>") }
    }

    @Test
    fun testMultipleDomainRegex() {
        val multi = RegexSet.fromExpressionList(listOf(exampleComRegex, pgpainlessOrgRegex))
        assertTrue { multi.matches("Bob <bob@example.com>") }
        assertTrue { multi.matches("Alice <alice@pgpainless.org>") }
        assertTrue { multi.matches("<info@pgpainless.org>") }
        assertFalse { multi.matches("Alice") }
        assertFalse { multi.matches("<info@examp1e.com>") }
    }
}