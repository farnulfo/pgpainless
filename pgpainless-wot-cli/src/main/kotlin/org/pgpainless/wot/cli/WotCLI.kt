// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli

import org.pgpainless.util.DateUtil
import org.pgpainless.wot.cli.subcommands.*
import org.pgpainless.wot.dijkstra.sq.ReferenceTime
import picocli.CommandLine
import picocli.CommandLine.*
import java.io.File
import java.util.concurrent.Callable
import kotlin.system.exitProcess

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

    @Option(names = ["--keyring", "-k"], description = ["Specify a keyring file."], required = true)
    var keyring: File? = null

    /*
    @Option(names = ["--gpg"], description = ["Read trust roots and keyring from GnuPG."])
    var gpg = false

    @Option(names = ["--network"], description = ["Look for missing certificates on a key server or the WKD."])
    var keyServer = "hkps://keyserver.ubuntu.com"

    @Option(names = ["--certification-network"], description = ["Treat the web of trust as a certification network instead of an authentication network."])
    var certificationNetwork = false

    @Option(names = ["--gossip"], description = ["Find arbitrary paths by treating all certificates as trust-roots with zero trust."])
    var gossip = false
     */

    @Option(names = ["--trust-amount", "-a"], description = ["The required amount of trust."])
    var amount = 1200

    @Option(names = ["--time"], description = ["Reference time."])
    var time: String? = null

    fun getReferenceTime(): ReferenceTime {
        return if (time == null) {
            ReferenceTime.now()
        } else {
            val date = DateUtil.parseUTCDate(time)
            ReferenceTime.timestamp(date)
        }
    }

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        require(trustRoot.isNotEmpty()) {
            "Expected at least one trust-root."
        }


        return 0
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>): Unit = exitProcess(CommandLine(WotCLI()).execute(*args))
    }
}
