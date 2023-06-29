// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.RevocationState
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
import org.pgpainless.wot.dijkstra.sq.CertificationSet.Companion.fromCertification
import org.pgpainless.wot.dijkstra.sq.ReferenceTime.Companion.now
import org.pgpainless.wot.util.CertificationFactory.Companion.fromCertification
import org.pgpainless.wot.util.CertificationFactory.Companion.fromDelegation
import org.slf4j.LoggerFactory
import pgp.cert_d.PGPCertificateDirectory
import pgp.certificate_store.certificate.Certificate
import java.io.IOException
import java.util.*

class WebOfTrust(private val certificateStore: PGPCertificateDirectory) {

    lateinit var network: Network

    fun initialize() {
        var trustRoot: Certificate? = null
        try {
            trustRoot = certificateStore.trustRootCertificate
        } catch (e: NoSuchElementException) {
            // ignore
        }

        val certificates = if (trustRoot == null) {
            certificateStore.items().asSequence()
        } else {
            sequenceOf(trustRoot) + certificateStore.items().asSequence()
        }

        network = fromCertificates(certificates, PGPainless.getPolicy(), now())
    }

    companion object {
        @JvmStatic
        fun fromCertificates(certificates: Sequence<Certificate>,
                             policy: Policy,
                             referenceTime: ReferenceTime): Network {
            return fromValidCertificates(
                    parseValidCertificates(certificates, policy, referenceTime),
                    policy,
                    referenceTime
            )
        }

        @JvmStatic
        fun fromValidCertificates(certificates: List<KeyRingInfo>,
                                  policy: Policy,
                                  referenceTime: ReferenceTime): Network {
            val nb = NetworkBuilder(certificates, policy, referenceTime)
            return nb.buildNetwork()
        }

        @JvmStatic
        private fun parseValidCertificates(certificates: Sequence<Certificate>,
                                           policy: Policy,
                                           referenceTime: ReferenceTime): List<KeyRingInfo> {
            return certificates
                    .mapNotNull { cert ->
                        try {
                            PGPainless.readKeyRing().publicKeyRing(cert.inputStream)
                        } catch (e: IOException) {
                            null
                        }
                    }
                    .map { cert ->
                        KeyRingInfo(cert, policy, referenceTime.timestamp)
                    }
                    .toList()
        }

        // Map signature to its revocation state
        @JvmStatic
        private fun revocationStateFromSignature(revocation: PGPSignature?): RevocationState {
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
         * Class for building the [Flow network][Network] from the given set of OpenPGP keys.
         *
         */
        private class NetworkBuilder constructor(validatedCertificates: List<KeyRingInfo>,
                                                 private val policy: Policy,
                                                 private val referenceTime: ReferenceTime) {

            private val LOGGER = LoggerFactory.getLogger(NetworkBuilder::class.java)

            // certificates keyed by fingerprint
            private val byFingerprint: MutableMap<OpenPgpFingerprint, KeyRingInfo> = HashMap()

            // certificates keyed by (sub-) key-id
            private val byKeyId: MutableMap<Long, MutableList<KeyRingInfo>> = HashMap()

            // certificate synopses keyed by fingerprint
            private val certSynopsisMap: MutableMap<OpenPgpFingerprint, CertSynopsis> = HashMap()

            // Issuer -> Targets, edges keyed by issuer
            private val edges: MutableMap<OpenPgpFingerprint, MutableList<CertificationSet>> = HashMap()

            // Target -> Issuers, edges keyed by target
            private val reverseEdges: MutableMap<OpenPgpFingerprint, MutableList<CertificationSet>> = HashMap()

            init {
                synopsizeCertificates(validatedCertificates)
                findEdges(validatedCertificates)
            }

            private fun synopsizeCertificates(validatedCertificates: List<KeyRingInfo>) {
                for (cert in validatedCertificates) {
                    synopsize(cert)
                }
            }

            private fun synopsize(cert: KeyRingInfo) {

                // index by fingerprint
                if (!byFingerprint.containsKey(cert.fingerprint)) {
                    byFingerprint[cert.fingerprint] = cert
                }

                // index by key-ID
                var certsWithKey = byKeyId[cert.keyId]
                // noinspection Java8MapApi
                if (certsWithKey == null) {
                    certsWithKey = mutableListOf()
                    // TODO: Something is fishy here...
                    for (key in cert.validSubkeys) {
                        byKeyId[key.keyID] = certsWithKey
                    }
                }
                certsWithKey.add(cert)
                val userIds: MutableMap<String, RevocationState> = HashMap()
                for (userId in cert.userIds) {
                    val state: RevocationState = revocationStateFromSignature(cert.getUserIdRevocation(userId))
                    userIds[userId] = state
                }

                // index synopses
                val expirationDate: Date? = try {
                    cert.getExpirationDateForUse(KeyFlag.CERTIFY_OTHER)
                } catch (e: NoSuchElementException) {
                    // Some keys are malformed and have no KeyFlags
                    return
                }
                certSynopsisMap[cert.fingerprint] = CertSynopsis(cert.fingerprint,
                        expirationDate,
                        revocationStateFromSignature(cert.revocationSelfSignature),
                        userIds)
            }

            private fun findEdges(validatedCertificates: List<KeyRingInfo>) {
                // Identify certifications and delegations
                // Target = cert carrying a signature
                for (validatedTarget in validatedCertificates) {
                    findEdgesWithTarget(validatedTarget)
                }
            }

            private fun findEdgesWithTarget(validatedTarget: KeyRingInfo) {
                val validatedTargetKeyRing = KeyRingUtils.publicKeys(validatedTarget.keys)
                val targetFingerprint = OpenPgpFingerprint.of(validatedTargetKeyRing)
                val targetPrimaryKey = validatedTargetKeyRing.publicKey!!
                val target = certSynopsisMap[targetFingerprint]!!

                // Direct-Key Signatures (delegations) by X on Y
                val delegations = SignatureUtils.getDelegations(validatedTargetKeyRing)
                for (delegation in delegations) {
                    processDelegation(targetPrimaryKey, target, delegation)
                }

                // Certification Signatures by X on Y over user-ID U
                val userIds = targetPrimaryKey.userIDs
                while (userIds.hasNext()) {
                    val userId = userIds.next()
                    val userIdSigs = SignatureUtils.get3rdPartyCertificationsFor(userId, validatedTargetKeyRing)
                    processCertification(targetPrimaryKey, target, userId, userIdSigs)
                }
            }

            private fun processDelegation(targetPrimaryKey: PGPPublicKey,
                                          target: CertSynopsis,
                                          delegation: PGPSignature) {
                val issuerCandidates = byKeyId[delegation.keyID]
                        ?: return
                for (candidate in issuerCandidates) {
                    val issuerKeyRing = KeyRingUtils.publicKeys(candidate.keys)
                    val issuerFingerprint = OpenPgpFingerprint.of(issuerKeyRing)
                    val issuerSigningKey = issuerKeyRing.getPublicKey(delegation.keyID)
                    val issuer = certSynopsisMap[issuerFingerprint]
                            ?: continue
                    try {
                        val valid = SignatureVerifier.verifyDirectKeySignature(delegation, issuerSigningKey,
                                targetPrimaryKey, policy, referenceTime.timestamp)
                        if (valid) {
                            indexEdge(fromDelegation(issuer, target, delegation))
                        }
                    } catch (e: SignatureValidationException) {
                        val targetFingerprint = OpenPgpFingerprint.of(targetPrimaryKey)
                        LOGGER.warn("Cannot verify signature by $issuerFingerprint on cert of $targetFingerprint", e)
                    }
                }
            }

            private fun processCertification(targetPrimaryKey: PGPPublicKey,
                                             target: CertSynopsis,
                                             userId: String,
                                             userIdSigs: List<PGPSignature>) {
                for (certification in userIdSigs) {
                    val issuerCandidates = byKeyId[certification.keyID]
                            ?: continue
                    for (candidate in issuerCandidates) {
                        val issuerKeyRing = KeyRingUtils.publicKeys(candidate.keys)
                        val issuerFingerprint = OpenPgpFingerprint.of(issuerKeyRing)
                        val issuerSigningKey = issuerKeyRing.getPublicKey(certification.keyID)
                                ?: continue
                        val issuer = certSynopsisMap[issuerFingerprint]
                                ?: continue
                        try {
                            val valid = SignatureVerifier.verifySignatureOverUserId(userId, certification,
                                    issuerSigningKey, targetPrimaryKey, policy, referenceTime.timestamp)
                            if (valid) {
                                indexEdge(fromCertification(issuer, target, userId, certification))
                            }
                        } catch (e: SignatureValidationException) {
                            LOGGER.warn("Cannot verify signature for '$userId' by $issuerFingerprint" +
                                    " on cert of ${target.fingerprint}", e)
                        }
                    }
                }
            }

            private fun indexEdge(certification: Certification) {
                // Index edge as outgoing edge for issuer
                val issuer = certification.issuer.fingerprint
                edges.getOrPut(issuer) { mutableListOf() }.also { indexOutEdge(it, certification) }

                // Index edge as incoming edge for target
                val target = certification.target.fingerprint
                reverseEdges.getOrPut(target) { mutableListOf() }.also { indexInEdge(it, certification) }
            }

            private fun indexOutEdge(outEdges: MutableList<CertificationSet>, certification: Certification) {
                val target = certification.target.fingerprint
                for (outEdge in outEdges) {
                    if (target == outEdge.target.fingerprint) {
                        outEdge.add(certification)
                        return
                    }
                }
                outEdges.add(fromCertification(certification))
            }

            private fun indexInEdge(inEdges: MutableList<CertificationSet>, certification: Certification) {
                val issuer = certification.issuer.fingerprint
                for (inEdge in inEdges) {
                    if (issuer == inEdge.issuer.fingerprint) {
                        inEdge.add(certification)
                        return
                    }
                }
                inEdges.add(fromCertification(certification))
            }

            /**
             * Return the constructed, initialized [Network].
             *
             * @return finished network
             */
            fun buildNetwork(): Network {
                return Network(certSynopsisMap, edges, reverseEdges, referenceTime)
            }
        }
    }
}
