// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.network

data class Root(val fingerprint: Fingerprint, val amount: Int) {

    constructor(fingerprint: Fingerprint) : this(fingerprint, 120)

    override fun toString() = "$fingerprint [$amount]"
}