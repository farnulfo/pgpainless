package org.pgpainless.wot.dijkstra.sq

import org.pgpainless.algorithm.RevocationState
import org.pgpainless.key.OpenPgpFingerprint
import java.util.*

data class CertSynopsis(
        val fingerprint: OpenPgpFingerprint,
        val expirationTime: Date?,
        val revocationState: RevocationState,
        val userIds : Map<String, RevocationState>) {

    override fun toString(): String {
        return if (userIds.isEmpty()) {
            "$fingerprint"
        } else {
            "$fingerprint (${userIds.keys.first()})"
        }
    }
}