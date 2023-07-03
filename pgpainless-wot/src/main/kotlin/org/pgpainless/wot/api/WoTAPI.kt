// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.api

import org.pgpainless.certificate_store.PGPainlessCertD
import org.pgpainless.util.NotationRegistry
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.ReferenceTime
import pgp.cert_d.PGPCertificateStoreAdapter
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookupFactory
import pgp.certificate_store.PGPCertificateStore

/**
 * Web of Trust API, offering different operations.
 *
 * @param certStores one or more [PGPCertificateStores][PGPCertificateStore] to retrieve certificates from.
 * @param trustRoots one or more [Fingerprints][Fingerprint] of trust-roots.
 * @param gossip if true, consider all certificates as weakly trusted trust-roots
 * @param certificationNetwork if true, all certifications are treated as delegations with infinite trust depth and no regular expressions
 * @param trustAmount minimum trust amount
 * @param referenceTime reference time at which the web of trust is evaluated
 * @param knownNotationRegistry registry of known notations
 */
class WoTAPI(
        val certStores: List<PGPCertificateStore> = getDefaultCertStores(),
        val trustRoots: List<Fingerprint>,
        val gossip: Boolean = false,
        val certificationNetwork: Boolean = false,
        val trustAmount: Int = AuthenticationLevel.Fully.amount,
        val referenceTime: ReferenceTime = ReferenceTime.now(),
        val knownNotationRegistry: NotationRegistry = NotationRegistry()
): AuthenticateAPI, IdentifyAPI, ListAPI, LookupAPI, PathAPI {

    /**
     * Secondary constructor, taking an [AuthenticationLevel] instead of an [Int].
     */
    constructor(certStores: List<PGPCertificateStore> = getDefaultCertStores(),
                trustRoots: List<Fingerprint>,
                gossip: Boolean = false,
                certificationNetwork: Boolean = false,
                trustAmount: AuthenticationLevel = AuthenticationLevel.Fully,
                referenceTime: ReferenceTime = ReferenceTime.now(),
                knownNotationRegistry: NotationRegistry = NotationRegistry()):
            this(certStores,trustRoots, gossip,certificationNetwork, trustAmount.amount, referenceTime, knownNotationRegistry)

    companion object {
        @JvmStatic
        fun getDefaultCertStores(): List<PGPCertificateStore> {
            val certD = PGPainlessCertD.fileBased(InMemorySubkeyLookupFactory())
            val asStore = PGPCertificateStoreAdapter(certD)
            return listOf(asStore)
        }
    }

    override fun authenticate(arguments: AuthenticateAPI.Arguments): AuthenticateAPI.Result {
        TODO("Not yet implemented")
    }

    override fun identify(arguments: IdentifyAPI.Arguments): IdentifyAPI.Result {
        TODO("Not yet implemented")
    }

    override fun list(): ListAPI.Result {
        TODO("Not yet implemented")
    }

    override fun lookup(arguments: LookupAPI.Arguments): LookupAPI.Result {
        TODO("Not yet implemented")
    }

    override fun path(arguments: PathAPI.Arguments): PathAPI.Result {
        TODO("Not yet implemented")
    }

}