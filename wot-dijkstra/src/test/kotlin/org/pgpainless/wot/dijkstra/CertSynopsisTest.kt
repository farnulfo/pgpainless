// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class CertSynopsisTest: NetworkDSL {

    @Test
    fun `Fingerprint 'A' toString`() {
        val node = CertSynopsis("A")
        assertEquals("A", node.toString())
    }

    @Test
    fun `Fingerprint 'a' toString`() {
        val node = CertSynopsis("a")
        assertEquals("A", node.toString())
    }

    @Test
    fun `Fingerprint 'A' and UserID toString`() {
        val node = CertSynopsis("A", "Alice <alice@example.org>")
        assertEquals("A (Alice <alice@example.org>)", node.toString())
    }
}