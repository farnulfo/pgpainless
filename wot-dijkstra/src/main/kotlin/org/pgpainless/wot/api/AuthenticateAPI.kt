// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.query.Paths

/**
 * Authenticate a binding.
 * A binding is a pair consisting of a certificate and a User ID.
 */
interface AuthenticateAPI {

    /**
     * Authenticate the binding between a fingerprint and a given userId.
     *
     * @param arguments arguments
     */
    fun authenticate(arguments: Arguments): Result

    /**
     * Bundle for arguments to the authenticate operation.
     * @param fingerprint fingerprint of the certificate
     * @param userId user-ID for which we want to authenticate a binding to the certificate
     * @param email if true, consider [userId] to be an email address and consider all bindings containing it
     */
    data class Arguments(
            var fingerprint: Fingerprint,
            var userId: String,
            var email: Boolean = false)

    /**
     * Authentication result.
     * @param targetAmount the targeted trust amount required to achieve full authentication
     * @param paths the number of paths
     */
    data class Result(val fingerprint: Fingerprint, val userId: String, private val targetAmount: Int, val paths: Paths) {

        /**
         * Percentage of authentication. 100% means fully authenticated binding.
         */
        val percentage: Int
            get() = paths.amount * 100 / targetAmount
    }

}
