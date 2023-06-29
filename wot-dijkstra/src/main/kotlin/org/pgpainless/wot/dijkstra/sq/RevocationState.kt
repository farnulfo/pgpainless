// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

import java.util.*

/**
 * Revocation State of
 */
class RevocationState private constructor(val type: Type, val timestamp: Date?) {

    enum class Type {
        Soft,
        Hard,
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
        return isHardRevocation() ||
                (isSoftRevocation() && referenceTime.timestamp.after(timestamp))
    }
}