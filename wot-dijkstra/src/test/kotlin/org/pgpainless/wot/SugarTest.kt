// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import kotlin.test.Test
import kotlin.test.assertEquals

class SugarTest {

    @Test
    fun `test letIf(predicate, block) with a predicate that evaluates to true`() {
        assertEquals("Hello, PGP!", "Hello, GPG!".letIf({ contains("GPG") }) {
            replace("GPG", "PGP")
        })
    }

    @Test
    fun `test letIf(predicate, block) with a predicate that evaluates to false`() {
        assertEquals("Hello, PGP!", "Hello, PGP!".letIf({ contains("GPG")}) {
            replace("Hello", "Salut")
        })
    }

    @Test
    fun `test letIf(condition, block) with true condition`() {
        assertEquals("hello, pgp!", "Hello, PGP!".letIf(true) {
            lowercase()
        })
    }

    @Test
    fun `test letIf(condition, block) with false condition`() {
        assertEquals("Hello, PGP!", "Hello, PGP!".letIf(false) {
            lowercase()
        })
    }

    @Test
    fun `test applyIf(predicate, block) with predicate that evaluates to true`() {
        assertEquals(listOf("A", "B", "C"), mutableListOf("A", "B").applyIf({ !contains("C") }) {
            add("C")
        })
    }

    @Test
    fun `test applyIf(predicate, block) with predicate that evaluates to false`() {
        assertEquals(listOf("A", "B", "C"), mutableListOf("A", "B", "C").applyIf({ !contains("C")}) {
            add("C")
        })
    }

    @Test
    fun `test applyIf(condition, block) with true condition`() {
        assertEquals(listOf("A", "B", "C"), mutableListOf("A", "B").applyIf(true) {
            add("C")
        })
    }

    @Test
    fun `test applyIf(condition, block) with false condition`() {
        assertEquals(listOf("A", "B"), mutableListOf("A", "B").applyIf(false) {
            add("C")
        })
    }
}