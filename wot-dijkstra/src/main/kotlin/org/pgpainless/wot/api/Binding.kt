// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.query.Path
import org.pgpainless.wot.query.Paths
import java.text.SimpleDateFormat

data class Binding(val fingerprint: Fingerprint, val userId: String, val paths: Paths) {
    /**
     * Percentage of authentication. 100% means fully authenticated binding.
     */
    fun percentage(targetAmount: Int): Int {
        return paths.amount * 100 / targetAmount
    }
}