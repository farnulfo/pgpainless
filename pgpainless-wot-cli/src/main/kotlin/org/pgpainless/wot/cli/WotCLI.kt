// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli

import org.pgpainless.PGPainless
import org.pgpainless.certificate_store.PGPainlessCertD
import org.pgpainless.util.DateUtil
import org.pgpainless.util.NotationRegistry
import org.pgpainless.wot.WebOfTrust
import org.pgpainless.wot.cli.subcommands.*
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.ReferenceTime
import org.pgpainless.wot.api.WoTAPI
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
    var trustRoot: Array<String> = arrayOf()

    @ArgGroup(exclusive = true, multiplicity = "1")
    lateinit var certificateSource: CertificateSource

    class CertificateSource {
        @Option(names = ["--keyring", "-k"], description = ["Specify a keyring file."], required = true)
        var keyring: File? = null

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
    lateinit var trustAmount: TrustAmount

    class TrustAmount {
        @Option(names = ["--trust-amount", "-a"], description = ["The required amount of trust."])
        var amount: Int? = null

        @Option(names = ["--partial"])
        var partial: Boolean = false
            set(value) {
                field = value
                if (field) {
                    amount = 40
                }
            }

        @Option(names = ["--full"])
        var full: Boolean = false
            set(value) {
                field = value
                if (field) {
                    amount = 120
                }
            }

        @Option(names = ["--double"])
        var double: Boolean = false
            set(value) {
                field = value
                if (field) {
                    amount = 240
                }
            }
    }


    @Option(names = ["--time"], description = ["Reference time."])
    var time: String? = null

    @Option(names = ["--known-notation"], description = ["Add a notation to the list of known notations."])
    var knownNotations: Array<String> = arrayOf()

    private val referenceTime: ReferenceTime
        get() {
            return time?.let {
                ReferenceTime.timestamp(DateUtil.parseUTCDate(time!!))
            } ?: ReferenceTime.now()
        }

    private val certificateStore: PGPCertificateStore
        get() {
            requireNotNull(certificateSource.pgpCertD) {
                "Currently, only --cert-d is supported."
            }
            val certD = PGPainlessCertD.fileBased(
                    certificateSource.pgpCertD,
                    InMemorySubkeyLookupFactory())

            return PGPCertificateStoreAdapter(certD)
        }

    private val trustRoots: List<Fingerprint>
        get() {
            return trustRoot.map { Fingerprint(it) }
        }

    val amount: Int
        get() =
            if (trustAmount.amount == null) {
                if (certificationNetwork) 1200 else 120
            } else trustAmount.amount!!

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        require(trustRoot.isNotEmpty()) {
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
                    gossip = false,
                    certificationNetwork = false,
                    trustAmount = amount,
                    referenceTime = referenceTime)
        }

    companion object {
        @JvmStatic
        fun main(args: Array<String>): Unit = exitProcess(CommandLine(WotCLI()).execute(*args))
    }
}
