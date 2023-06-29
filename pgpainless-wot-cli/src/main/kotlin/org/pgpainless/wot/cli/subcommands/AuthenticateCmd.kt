// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.api.AuthenticateAPI
import org.pgpainless.wot.cli.WotCLI
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import picocli.CommandLine.ParentCommand
import java.util.concurrent.Callable

@Command(name = "authenticate")
class AuthenticateCmd: Callable<Int> {

    @ParentCommand
    lateinit var parent: WotCLI

    @Parameters(index = "0")
    lateinit var fingerprint: String

    @Parameters(index = "1")
    lateinit var userId: String

    @CommandLine.Option(names = ["--email"], description = ["Consider all user-IDs that contain the given email address."])
    var email = false

    /**
     * Execute the command.
     * @return exit code
     */
    override fun call(): Int {
        val api = AuthenticateAPI()
        TODO("Not yet implemented")
    }
}