package org.pgpainless.wot.testfixtures

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.CertificationSubpackets
import org.pgpainless.signature.subpackets.CertificationSubpackets.Callback
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import pgp.certificate_store.PGPCertificateStore

interface AdHocVectors {

    /**
     * When doing backwards propagation, we find paths from all nodes to the
     * target.  Since we don't stop when we reach a root, the returned path
     * should still be optimal.  Consider:
     *
     * A --- 120/10 ---> B --- 120/10 ---> C --- 120/10 ---> Target
     *  \                                                      /
     *   `--- 50/10 ---> Y --- 50/10 ---> Z --- 50/10 --------'
     * When the root is B, then the path that we find for A should be A -> B -> C -> Target, not A -> Y -> Z -> Target.
     */
    class BestViaRoot : AdHocVectors {
        val aliceUID: String = "Alice <alice@pgpainless.org>"
        val aliceKey: PGPSecretKeyRing = PGPainless.generateKeyRing().modernKeyRing(aliceUID)
        val aliceCert = PGPPublicKeyRing(aliceKey)
        val aliceFingerprint = Fingerprint(aliceKey)

        val bobUID = "Bob <bob@pgpainless.org>"
        val bobKey: PGPSecretKeyRing = PGPainless.generateKeyRing().simpleRsaKeyRing(bobUID, RsaLength._3072)
        val bobCert = PGPPublicKeyRing(bobKey)
        val bobFingerprint = Fingerprint(bobKey)

        val carolUID = "Carol <carol@example.com>"
        val carolKey: PGPSecretKeyRing = PGPainless.generateKeyRing().simpleEcKeyRing(carolUID)
        val carolCert = PGPPublicKeyRing(carolKey)
        val carolFingerprint = Fingerprint(carolKey)

        val targetUID = "Tanja <tanja@target.tld>"
        val targetKey: PGPSecretKeyRing = PGPainless.generateKeyRing().modernKeyRing(targetUID)
        val targetCert = PGPPublicKeyRing(targetKey)
        val targetFingerprint = Fingerprint(targetKey)

        val yellowUID = "Yellow <yellow@alternate.path>"
        val yellowKey: PGPSecretKeyRing = PGPainless.generateKeyRing().modernKeyRing(yellowUID)
        val yellowCert = PGPPublicKeyRing(yellowKey)
        val yellowFingerprint = Fingerprint(yellowKey)

        val zebraUID = "Zebra <zebra@alternate.path>"
        val zebraKey: PGPSecretKeyRing = PGPainless.generateKeyRing().modernKeyRing(zebraUID)
        val zebraCert = PGPPublicKeyRing(zebraKey)
        val zebraFingerprint = Fingerprint(zebraKey)

        override val publicKeyRingCollection: PGPPublicKeyRingCollection
            get() {
                val signedCerts = listOf(
                        targetCert.let {
                            // C ---120/10--> Target
                            certify(issuer = carolKey, target = it, amount = 120, depth = 10)
                        }.let {
                            // Z ---50/10---> Target
                            certify(issuer = zebraKey, target = it, amount = 50, depth = 10)
                        },
                        carolCert.let {
                            // B ---120/10--> C
                            certify(issuer = bobKey, target = it, amount = 120, depth = 10)
                        },
                        bobCert.let {
                            // A ---120/10--> B
                            certify(issuer = aliceKey, target = it, amount = 120, depth = 10)
                        },
                        zebraCert.let {
                            // Y ---50/10--> Z
                            certify(issuer = yellowKey, target = it, amount = 50, depth = 10)
                        },
                        yellowCert.let {
                            // A ---50/10--> Y
                            certify(issuer = aliceKey, target = it, amount = 50, depth = 10)
                        })
                return PGPPublicKeyRingCollection(signedCerts)
            }
    }

    val publicKeyRingCollection: PGPPublicKeyRingCollection

    val pgpCertificateStore: PGPCertificateStore
        get() = KeyRingCertificateStore(publicKeyRingCollection)

    fun certify(issuer: PGPSecretKeyRing,
                target: PGPPublicKeyRing,
                userId: String = target.publicKey.userIDs.next()!!,
                amount: Int,
                depth: Int): PGPPublicKeyRing = PGPainless.certify()
            .userIdOnCertificate(userId, target)
            .withKey(issuer, SecretKeyRingProtector.unprotectedKeys())
            .buildWithSubpackets(object : Callback {
                override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets?) {
                    hashedSubpackets!!.setTrust(depth, amount)
                }
            }).certifiedCertificate

    fun PGPPublicKeyRing(secretKey: PGPSecretKeyRing): PGPPublicKeyRing =
            PGPainless.extractCertificate(secretKey)

    fun Fingerprint(keyRing: PGPKeyRing): Fingerprint =
            Fingerprint(OpenPgpFingerprint.of(keyRing).toString())
}