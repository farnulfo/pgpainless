// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

data class Root(val fingerprint: Fingerprint, val amount: Int) {

    override fun toString() = "$fingerprint [$amount]"
}