package org.pgpainless.wot.dijkstra.sq

import kotlin.test.Test

class RegexSetTest {

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

}