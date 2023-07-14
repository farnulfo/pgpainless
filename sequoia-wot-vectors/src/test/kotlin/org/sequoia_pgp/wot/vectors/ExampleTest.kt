// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.junit.jupiter.api.Test
import org.pgpainless.wot.network.ReferenceTime

class ExampleTest {

    @Test
    fun test() {
        val vectors = BestViaRootVectors()
        val network = vectors.getNetworkAt(ReferenceTime.now())
        println(network)
    }
}