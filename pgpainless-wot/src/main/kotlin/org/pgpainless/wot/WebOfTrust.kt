// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.policy.Policy
import org.pgpainless.signature.SignatureUtils
import org.pgpainless.signature.consumer.SignatureVerifier
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.wot.dijkstra.sq.*
import org.pgpainless.wot.dijkstra.sq.ReferenceTime.Companion.now
import org.pgpainless.wot.util.CertificationFactory.Companion.fromCertification
import org.pgpainless.wot.util.CertificationFactory.Companion.fromDelegation
import org.slf4j.LoggerFactory
import pgp.cert_d.PGPCertificateDirectory
import pgp.cert_d.PGPCertificateStoreAdapter
import pgp.cert_d.SpecialNames
import pgp.certificate_store.PGPCertificateStore
import pgp.certificate_store.certificate.Certificate
import java.io.IOException
import java.util.*

/**
 * Create a [WebOfTrust] based on a [PGPCertificateStore] instance.
 *
 * @param certificateStore certificate store
 */
class WebOfTrust(private val certificateStore: PGPCertificateStore) {

    /**
     * Create a [WebOfTrust] based on a [PGPCertificateDirectory] instance, which gets adapted to the
     * [PGPCertificateStore] interface.
     *
     * @param certificateDirectory PGP-Certificate-Directory instance
     */
    constructor(certificateDirectory: PGPCertificateDirectory): this(PGPCertificateStoreAdapter(certificateDirectory))

    fun buildNetwork(policy: Policy = PGPainless.getPolicy(), referenceTime: ReferenceTime = now()): Network {
        val certificates = getAllCertificatesFromTheStore()
        val networkFactory = PGPNetworkFactory.fromCertificates(certificates, policy, referenceTime)
        return networkFactory.buildNetwork()
    }

    private fun getAllCertificatesFromTheStore(): Sequence<Certificate> {
        var trustRoot: Certificate? = null
        try {
            trustRoot = certificateStore.getCertificate(SpecialNames.TRUST_ROOT)
        } catch (e: NoSuchElementException) {
            // ignore
        }

        val certificates = if (trustRoot == null) {
            certificateStore.certificates.asSequence()
        } else {
            sequenceOf(trustRoot) + certificateStore.certificates.asSequence()
        }
        return certificates
    }

    /**
     * Class for building the [Flow network][Network] from the given set of OpenPGP keys.
     *
     * @param validatedCertificates list of validated certificates
     * @param policy policy for signature evaluation
     * @param referenceTime reference time for network evaluation
     */
    private class PGPNetworkFactory private constructor(validatedCertificates: List<KeyRingInfo>,
                                                        private val policy: Policy,
                                                        private val referenceTime: ReferenceTime) {
        private val networkBuilder: Network.Builder = Network.builder()

        // certificates keyed by fingerprint
        private val byFingerprint: MutableMap<Fingerprint, KeyRingInfo> = HashMap()

        // certificates keyed by (sub-) key-id
        private val byKeyId: MutableMap<Long, MutableList<KeyRingInfo>> = HashMap()

        // nodes keyed by fingerprint
        private val nodeMap: MutableMap<Fingerprint, CertSynopsis> = HashMap()

        init {
            validatedCertificates.forEach { indexAsNode(it) }
            validatedCertificates.forEach { indexIncomingEdges(it) }
        }

        /**
         * Index the certificate by its [Fingerprint] and subkey-IDs and add it as a node to
         * the [Network.Builder].
         *
         * @param cert validated certificate
         */
        private fun indexAsNode(cert: KeyRingInfo) {

            // certificate expiration date
            val expirationDate: Date? = try {
                cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER)
            } catch (e: NoSuchElementException) {
                // Some keys are malformed and have no KeyFlags
                return
            }

            // index by fingerprint
            val certFingerprint = Fingerprint(cert.fingerprint)
            byFingerprint.putIfAbsent(certFingerprint, cert)

            // index by key-ID
            cert.validSubkeys.forEach {
                byKeyId.getOrPut(it.keyID) { mutableListOf() }.add(cert)
            }

            // map user-ids to revocation states
            val userIds = buildMap<String, RevocationState> {
                cert.userIds.forEach {
                    put(it, RevocationState(cert.getUserIdRevocation(it)))
                }
            }

            val node = CertSynopsis(certFingerprint,
                    expirationDate,
                    RevocationState(cert.revocationSelfSignature),
                    userIds)

            nodeMap[certFingerprint] = node
            networkBuilder.addNode(node)
        }

        /**
         * Add all verifiable certifications on the certificate as incoming edges to
         * the [Network.Builder].
         *
         * @param validatedTarget validated certificate
         */
        private fun indexIncomingEdges(validatedTarget: KeyRingInfo) {
            val validatedTargetKeyRing = KeyRingUtils.publicKeys(validatedTarget.keys)
            val targetFingerprint = Fingerprint(OpenPgpFingerprint.of(validatedTargetKeyRing))
            val targetPrimaryKey = validatedTargetKeyRing.publicKey!!
            val target = nodeMap[targetFingerprint]!!

            // Direct-Key Signatures (delegations) by X on Y
            val delegations = SignatureUtils.getDelegations(validatedTargetKeyRing)
            for (delegation in delegations) {
                processDelegation(targetPrimaryKey, target, delegation)
            }

            // Certification Signatures by X on Y over user-ID U
            val userIds = targetPrimaryKey.userIDs
            while (userIds.hasNext()) {
                val userId = userIds.next()
                // There are potentially multiple certifications per user-ID
                val userIdSigs = SignatureUtils.get3rdPartyCertificationsFor(userId, validatedTargetKeyRing)
                userIdSigs.forEach {
                    processCertificationOnUserId(targetPrimaryKey, target, userId, it)
                }
            }
        }

        /**
         * Process a delegation signature (direct-key signature issued by a third-party certificate)
         * and add it upon successful verification as an edge to the [Network.Builder].
         *
         * @param targetPrimaryKey public primary key of the target certificate
         * @param target target certificate node
         * @param delegation delegation signature
         */
        private fun processDelegation(targetPrimaryKey: PGPPublicKey,
                                      target: CertSynopsis,
                                      delegation: PGPSignature) {
            // There might be more than one cert with a subkey of matching key-id
            val issuerCandidates = byKeyId[delegation.keyID]
                    ?: return // missing issuer cert

            for (candidate in issuerCandidates) {
                val issuerKeyRing = KeyRingUtils.publicKeys(candidate.keys)
                val issuerFingerprint = Fingerprint(OpenPgpFingerprint.of(issuerKeyRing))
                val issuerSigningKey = issuerKeyRing.getPublicKey(delegation.keyID)!!
                val issuer = nodeMap[issuerFingerprint]!!

                try {
                    val valid = SignatureVerifier.verifyDirectKeySignature(delegation, issuerSigningKey,
                            targetPrimaryKey, policy, referenceTime.timestamp)
                    if (valid) {
                        networkBuilder.addEdge(fromDelegation(issuer, target, delegation))
                        return // we're done
                    }
                } catch (e: SignatureValidationException) {
                    val targetFingerprint = OpenPgpFingerprint.of(targetPrimaryKey)
                    LOGGER.warn("Cannot verify signature by $issuerFingerprint on cert of $targetFingerprint", e)
                }
            }
        }

        /**
         * Process a certification (third-party-issued certification over the given [userId])
         * and add it upon successful verification as an edge to the [Network.Builder].
         *
         * @param targetPrimaryKey public primary key of the target certificate
         * @param target target certificate node
         * @param userId target user-id over which the [certification] is calculated
         * @param certification certification signature
         */
        private fun processCertificationOnUserId(targetPrimaryKey: PGPPublicKey,
                                                 target: CertSynopsis,
                                                 userId: String,
                                                 certification: PGPSignature) {
            // There might be more than one cert with a subkey of matching key-id
            val issuerCandidates = byKeyId[certification.keyID]
                    ?: return // missing issuer cert

            for (candidate in issuerCandidates) {
                val issuerKeyRing = KeyRingUtils.publicKeys(candidate.keys)
                val issuerFingerprint = Fingerprint(OpenPgpFingerprint.of(issuerKeyRing))
                val issuerSigningKey = issuerKeyRing.getPublicKey(certification.keyID)!!
                val issuer = nodeMap[issuerFingerprint]!!

                try {
                    val valid = SignatureVerifier.verifySignatureOverUserId(userId, certification,
                            issuerSigningKey, targetPrimaryKey, policy, referenceTime.timestamp)
                    if (valid) {
                        networkBuilder.addEdge(fromCertification(issuer, target, userId, certification))
                        return // we're done
                    }
                } catch (e: SignatureValidationException) {
                    LOGGER.warn("Cannot verify signature for '$userId' by $issuerFingerprint" +
                            " on cert of ${target.fingerprint}", e)
                }
            }
        }

        /**
         * Map an [OpenPgpFingerprint] to a [Fingerprint].
         *
         * @param fingerprint [OpenPgpFingerprint]
         */
        private fun Fingerprint(fingerprint: OpenPgpFingerprint) = Fingerprint(fingerprint.toString())

        /**
         * Map a [PGPSignature] to its [RevocationState].
         *
         * @param revocation optional revocation signature
         */
        private fun RevocationState(revocation: PGPSignature?): RevocationState {
            if (revocation == null) {
                return RevocationState.notRevoked()
            }
            val revocationReason = SignatureSubpacketsUtil.getRevocationReason(revocation)
                    ?: return RevocationState.hardRevoked()
            return if (RevocationAttributes.Reason.isHardRevocation(revocationReason.revocationReason))
                RevocationState.hardRevoked()
            else
                RevocationState.softRevoked(revocation.creationTime)
        }

        /**
         * Return the constructed, initialized [Network].
         *
         * @return finished network
         */
        fun buildNetwork(): Network {
            return networkBuilder.build()
        }

        // static factory methods
        companion object {
            @JvmStatic
            private val LOGGER = LoggerFactory.getLogger(PGPNetworkFactory::class.java)

            /**
             * Create a [PGPNetworkFactory] from a [Sequence] of [Certificates][Certificate].
             * This method validates the certificates and then creates a [PGPNetworkFactory] from them.
             *
             * @param certificates certificates, e.g. acquired from a [PGPCertificateStore]
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for network evaluation
             */
            @JvmStatic
            fun fromCertificates(certificates: Sequence<Certificate>,
                                 policy: Policy,
                                 referenceTime: ReferenceTime): PGPNetworkFactory {
                return fromValidCertificates(
                        parseValidCertificates(certificates, policy, referenceTime),
                        policy,
                        referenceTime
                )
            }

            /**
             * Create a [PGPNetworkFactory] from a list of [validated certificates][KeyRingInfo].
             *
             * @param certificates already validated certificates
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for network evaluation
             */
            @JvmStatic
            fun fromValidCertificates(certificates: List<KeyRingInfo>,
                                      policy: Policy,
                                      referenceTime: ReferenceTime): PGPNetworkFactory {
                return PGPNetworkFactory(certificates, policy, referenceTime)
            }

            /**
             * Evaluate the given [Sequence] of [Certificates][Certificate] and transform it into a
             * [List] of [validated certificates][KeyRingInfo].
             *
             * @param certificates certificates
             * @param policy policy for signature evaluation
             * @param referenceTime reference time for signature evaluation
             */
            @JvmStatic
            private fun parseValidCertificates(certificates: Sequence<Certificate>,
                                               policy: Policy,
                                               referenceTime: ReferenceTime): List<KeyRingInfo> {
                return certificates
                        .mapNotNull {
                            try { PGPainless.readKeyRing().publicKeyRing(it.inputStream) } catch (e: IOException) { null }
                        }
                        .map { KeyRingInfo(it, policy, referenceTime.timestamp) }
                        .toList()
            }
        }
    }
}
