// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.cli.WotCLI
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import java.util.concurrent.Callable

@Command(name = "path", description = ["Verify and lint a path."])
class PathCmd: Callable<Int> {

    @CommandLine.ParentCommand
    lateinit var parent: WotCLI

    @Parameters(index = "*",
            arity = "2..*",
            description = ["List of fingerprints starting with the roots fingerprint or key ID and ending with the target certificates fingerprint or key ID and a user ID."],
            )
    lateinit var keyIdsOrFingerprints: Array<String>

    /**
     * Execute the command.
     *
     * @return exit code
     */
    override fun call(): Int {
        val api = parent.api
        TODO("Not yet implemented")
    }
}