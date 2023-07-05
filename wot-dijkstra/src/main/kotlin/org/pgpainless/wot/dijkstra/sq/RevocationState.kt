// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*
import kotlin.math.abs

/**
 * Revocation State of a certificate.
 */
class RevocationState private constructor(val type: Type, val timestamp: Date?) {

    enum class Type {
        /**
         * Signatures issued by a soft-revoked certificate after [timestamp] are no longer
         * considered valid.
         */
        Soft,

        /**
         * Signatures issued at any time by a hard-revoked certificate are no longer considered valid,
         * even if the creation time is before [timestamp].
         */
        Hard,

        /**
         * The certificate is still valid.
         */
        None
    }

    companion object {
        @JvmStatic
        fun notRevoked(): RevocationState = RevocationState(Type.None, null)

        @JvmStatic
        fun softRevoked(timestamp: Date): RevocationState = RevocationState(Type.Soft, timestamp)

        @JvmStatic
        fun hardRevoked(): RevocationState = RevocationState(Type.Hard, null)
    }

    fun isHardRevocation(): Boolean = type == Type.Hard

    fun isSoftRevocation(): Boolean = type == Type.Soft

    fun isNotRevoked(): Boolean = type == Type.None

    fun isEffective(referenceTime: ReferenceTime): Boolean {
        if (isHardRevocation()) {
            return true
        }
        if (isSoftRevocation()) {
            if (referenceTime.timestamp.after(timestamp)) {
                return true
            }
            // return equal
            return abs(referenceTime.timestamp.time / 1000 - timestamp!!.time / 1000) == 0L // less than one second diff
        }
        return false
    }
}