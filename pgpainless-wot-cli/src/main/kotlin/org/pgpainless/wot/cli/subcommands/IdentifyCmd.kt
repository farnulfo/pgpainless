// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.api.IdentifyAPI
import org.pgpainless.wot.cli.WotCLI
import org.pgpainless.wot.network.Fingerprint
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import java.text.SimpleDateFormat
import java.util.concurrent.Callable

@Command(name = "identify")
class IdentifyCmd: Callable<Int> {

    @CommandLine.ParentCommand
    lateinit var parent: WotCLI

    @Parameters(index = "0", description = ["Certificate fingerprint."])
    lateinit var fingerprint: String

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        val result = parent.api.identify(IdentifyAPI.Arguments(Fingerprint(fingerprint)))

        print(parent.formatter.format(result))
        return if (result.acceptable) 0 else 1
    }
}