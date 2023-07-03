// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

/**
 * Enum for different levels of Trust.
 */
enum class AuthenticationLevel(val amount: Int) {
    /**
     * With an amount of 40, a binding is considered partially trusted.
     */
    Partially(40),

    /**
     * An amount if 120 is sufficient to fully authenticate a binding.
     */
    Fully(120),

    /**
     * A trust amount of 240 means the binding is doubly authenticated.
     */
    Doubly(240)
}