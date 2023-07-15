package org.pgpainless.wot.network

import org.junit.jupiter.api.Test
import org.pgpainless.wot.dsl.NetworkDSL
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RegexSetTest: NetworkDSL {

    private val exampleComRegex = "<[^>]+[@.]example\\.com>\$"
    private val pgpainlessOrgRegex = "<[^>]+[@.]pgpainless\\.org>\$"

    @Test
    fun simpleMatch() {
        val stringList: List<String> = listOf("<[^>]+[@.]foobank\\.com>$")
        val rs = RegexSet.fromExpressionList(stringList);

        assert(rs.matches("Foo Bank Employee <employee@foobank.com>"))
        assert(rs.matches("<employee@foobank.com>"))
    }

    @Test
    fun simpleNonMatch() {
        val stringList: List<String> = listOf("<[^>]+[@.]foobank\\.com>$")
        val rs = RegexSet.fromExpressionList(stringList);

        assert(!rs.matches("Bar Bank Employee <employee@barbank.com>"))
        assert(!rs.matches("<employee@barbank.com>"))
    }

    @Test
    fun `verify that the wildcard RegexSet matches anything`() {
        val wildcard = RegexSet.wildcard()
        assertTrue { wildcard.matches("Alice <alice@pgpainless.org>") }
        assertTrue { wildcard.matches("Bob <bob@example.com>") }
        assertTrue { wildcard.matches("") }
        assertTrue { wildcard.matches("X Æ A-12") }
    }

    @Test
    fun `verify that a single domain regex only matches UIDs from that domain`() {
        val exampleCom = RegexSet.fromExpression(exampleComRegex)
        assertTrue { exampleCom.matches("Bob <bob@example.com>") }
        assertTrue { exampleCom.matches("<admin@example.com>") }

        assertFalse { exampleCom.matches("Spoofed <bob@examp1e.com>") }
        assertFalse { exampleCom.matches("Alice <alice@pgpainless.org>") }
    }

    @Test
    fun `verify that a RegexSet built from two different domain regexes only matches UIDs from either of the domains`() {
        val multi = RegexSet.fromExpressionList(listOf(exampleComRegex, pgpainlessOrgRegex))
        assertTrue { multi.matches("Bob <bob@example.com>") }
        assertTrue { multi.matches("Alice <alice@pgpainless.org>") }
        assertTrue { multi.matches("<info@pgpainless.org>") }

        assertFalse { multi.matches("Alice") }
        assertFalse { multi.matches("<info@examp1e.com>") }
    }

    @Test
    fun `verify that a domain regex built with DLS properly works`() {
        val regex = domainRegex("pgpainless.org")
        assertTrue { regex.matches("Alice <alice@pgpainless.org>") }
        assertFalse { regex.matches("<alice@pgpainless\\.org>") }
    }

    @Test
    fun `verify that wildcard()_toString() equals empty string`() {
        val regex = RegexSet.wildcard()
        assertEquals("", regex.toString())
    }

    @Test
    fun `verify that single regex _toString() returns the regex`() {
        val regex = domainRegex("pgpainless.org")
        assertEquals("<[^>]+[@.]pgpainless\\.org>\$", regex.toString())
    }

    @Test
    fun `verify that multiple regex _toString returns comma separated values`() {
        val list = listOf("<[^>]+[@.]pgpainless\\.org>\$", "<[^>]+[@.]example\\.com>\$")
        val regex = RegexSet.fromExpressionList(list)
        assertEquals("<[^>]+[@.]pgpainless\\.org>\$, <[^>]+[@.]example\\.com>\$", regex.toString())
    }
}