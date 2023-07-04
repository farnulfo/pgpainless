package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.algorithm.RevocationStateType
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.wot.dijkstra.sq.CertSynopsis
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.RevocationState

interface PGPDSL {

    fun CertSynopsis(certificate: PGPPublicKeyRing): CertSynopsis {
        return CertSynopsis(Fingerprint(certificate), )
    }

    fun CertSynopsis(validatedCert: KeyRingInfo): CertSynopsis {
        return CertSynopsis(
                Fingerprint(validatedCert.fingerprint),
                validatedCert.primaryKeyExpirationDate,
                RevocationState(validatedCert.revocationState),
                validatedCert.userIds.associateWith{
                    RevocationState(validatedCert.getUserIdRevocation(it))
                })
    }

    fun Fingerprint(certificate: PGPPublicKeyRing): Fingerprint {
        return Fingerprint(OpenPgpFingerprint.of(certificate))
    }

    fun Fingerprint(pgpFingerprint: OpenPgpFingerprint): Fingerprint {
        return Fingerprint(pgpFingerprint.toString())
    }

    fun RevocationState(signature: PGPSignature?): RevocationState {
        return WebOfTrust.RevocationState(signature)
    }

    fun RevocationState(pgpRevocationState: org.pgpainless.algorithm.RevocationState): RevocationState {
        return when(pgpRevocationState.type) {
            RevocationStateType.hardRevoked -> RevocationState.hardRevoked()
            RevocationStateType.notRevoked -> RevocationState.notRevoked()
            else -> RevocationState.softRevoked(pgpRevocationState.date)
        }
    }
}