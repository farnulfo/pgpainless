// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli

import org.pgpainless.PGPainless
import org.pgpainless.certificate_store.PGPainlessCertD
import org.pgpainless.util.DateUtil
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.WebOfTrust
import org.pgpainless.wot.api.WoTAPI
import org.pgpainless.wot.cli.subcommands.*
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.ReferenceTime
import pgp.cert_d.PGPCertificateStoreAdapter
import pgp.cert_d.subkey_lookup.InMemorySubkeyLookupFactory
import pgp.certificate_store.PGPCertificateStore
import picocli.CommandLine
import picocli.CommandLine.*
import java.io.File
import java.util.concurrent.Callable
import kotlin.system.exitProcess

/**
 * Command Line Interface for pgpainless-wot, modelled after the reference implementation "sq-wot".
 *
 * @see <a href="https://gitlab.com/sequoia-pgp/sequoia-wot/">Sequoia Web of Trust Reference Implementation</a>
 */
@Command(name = "pgpainless-wot",
        subcommands = [
            AuthenticateCmd::class,
            IdentifyCmd::class,
            ListCmd::class,
            LookupCmd::class,
            PathCmd::class,
            HelpCommand::class
        ]
)
class WotCLI: Callable<Int> {

    @Option(names = ["--trust-root", "-r"], required = true)
    var mTrustRoot: Array<String> = arrayOf()

    @ArgGroup(exclusive = true, multiplicity = "1")
    lateinit var mCertificateSource: CertificateSource

    class CertificateSource {
        @Option(names = ["--keyring", "-k"], description = ["Specify a keyring file."], required = true)
        var keyring: Array<File>? = null

        @Option(names = ["--cert-d"], description = ["Specify a pgp-cert-d base directory."], required = true)
        var pgpCertD: File? = null

        @Option(names = ["--gpg"], description = ["Read trust roots and keyring from GnuPG."])
        var gpg = false
    }

    /*
    @Option(names = ["--network"], description = ["Look for missing certificates on a key server or the WKD."])
    var network: Boolean = false

    @Option(names = ["--keyserver"], description=["Change the default keyserver"])
    var keyServer: String = "hkps://keyserver.ubuntu.com"

    @Option(names = ["--gpg-ownertrust"])
    var gpgOwnertrust: Boolean = false
     */

    @Option(names = ["--certification-network"], description = ["Treat the web of trust as a certification network instead of an authentication network."])
    var certificationNetwork = false

    @Option(names = ["--gossip"], description = ["Find arbitrary paths by treating all certificates as trust-roots with zero trust."])
    var gossip = false

    @ArgGroup(exclusive = true, multiplicity = "1")
    lateinit var mTrustAmount: TrustAmount

    class TrustAmount {
        @Option(names = ["--trust-amount", "-a"], description = ["The required amount of trust."])
        var amount: Int? = null

        @Option(names = ["--partial"])
        var partial: Boolean = false

        @Option(names = ["--full"])
        var full: Boolean = false

        @Option(names = ["--double"])
        var double: Boolean = false
    }


    @Option(names = ["--time"], description = ["Reference time."])
    var mTime: String? = null

    @Option(names = ["--known-notation"], description = ["Add a notation to the list of known notations."])
    var knownNotations: Array<String> = arrayOf()

    private val referenceTime: ReferenceTime
        get() {
            return mTime?.let {
                ReferenceTime.timestamp(DateUtil.parseUTCDate(mTime!!))
            } ?: ReferenceTime.now()
        }

    private val trustRoots: List<Fingerprint>
        get() {
            if (mCertificateSource.gpg) {
                return readGpgOwnertrust().plus(mTrustRoot.map { Fingerprint(it) })
            }

            return mTrustRoot.map { Fingerprint(it) }
        }

    private val amount: Int
        get() = when {
            mTrustAmount.amount != null -> mTrustAmount.amount!!  // --amount=XY
            mTrustAmount.partial -> 40                           // --partial
            mTrustAmount.full -> 120                             // --full
            mTrustAmount.double -> 240                           // --double
            else -> if (certificationNetwork) 1200 else 120     // default 120, if --certification-network -> 1200
        }

    private val certificateStore: PGPCertificateStore
        get() {
            if (mCertificateSource.gpg) {
                return KeyRingCertificateStore(
                        PGPainless.readKeyRing().publicKeyRingCollection(
                                Runtime.getRuntime().exec("/usr/bin/gpg --export").inputStream
                        )
                )
            }
            if (mCertificateSource.keyring != null) {
                return KeyRingCertificateStore(
                        mCertificateSource.keyring!!.map {
                            PGPainless.readKeyRing().publicKeyRingCollection(it.inputStream())
                        }
                )
            }

            val certD = PGPainlessCertD.fileBased(
                    mCertificateSource.pgpCertD,
                    InMemorySubkeyLookupFactory())
            return PGPCertificateStoreAdapter(certD)
        }

    fun readGpgOwnertrust(): List<Fingerprint> = Runtime.getRuntime()
            .exec("/usr/bin/gpg --export-ownertrust")
            .inputStream
            .bufferedReader()
            .readLines()
            .filterNot { it.startsWith("#") }
            .filterNot { it.isBlank() }
            .map { it.substring(0, it.indexOf(':')) }
            .map { Fingerprint(it) }

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        require(mTrustRoot.isNotEmpty()) {
            "Expected at least one trust-root."
        }

        for (notation in knownNotations) {
            PGPainless.getPolicy().notationRegistry.addKnownNotation(notation)
        }

        return 0
    }

    val api: WoTAPI
        get() {
            val network = WebOfTrust(certificateStore)
                    .buildNetwork(referenceTime = referenceTime)
            return WoTAPI(
                    network = network,
                    trustRoots = trustRoots,
                    gossip = gossip,
                    certificationNetwork = certificationNetwork,
                    trustAmount = amount,
                    referenceTime = referenceTime)
        }

    companion object {

        @JvmStatic
        fun main(args: Array<String>): Unit = exitProcess(
                CommandLine(WotCLI()).execute(*args)
        )

    }

    override fun toString(): String {
        val source = if (mCertificateSource.gpg) {
            "gpg"
        } else {
            mCertificateSource.pgpCertD ?: mCertificateSource.keyring?.contentToString() ?: "null"
        }
        return "trustroot=${trustRoots}, source=$source, gossip=$gossip, amount=$amount," +
                " referenceTime=${referenceTime.timestamp}, notations=${knownNotations.contentToString()}"
    }
}
