// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.api.AuthenticateAPI
import org.pgpainless.wot.cli.WotCLI
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.query.Path
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import picocli.CommandLine.ParentCommand
import java.text.SimpleDateFormat
import java.util.concurrent.Callable

/**
 * Authenticate a binding between a certification and one of its user-ids.
 */
@Command(name = "authenticate")
class AuthenticateCmd: Callable<Int> {

    /**
     * Parent command to acquire global options from.
     */
    @ParentCommand
    lateinit var parent: WotCLI

    /**
     * Fingerprint of the certificate.
     */
    @Parameters(index = "0")
    lateinit var fingerprint: String

    /**
     * User-ID to authenticate.
     */
    @Parameters(index = "1")
    lateinit var userId: String

    /**
     * Handle the User-ID as an email address.
     */
    @CommandLine.Option(names = ["--email"], description = ["Consider all user-IDs that contain the given email address."])
    var email = false



    /**
     * Execute the command.
     * @return exit code
     */
    override fun call(): Int {
        val result = parent.api.authenticate(AuthenticateAPI.Arguments(
                Fingerprint(fingerprint), userId, email))
        formatResult(result)
        if (result.percentage < 100) {
            return -1
        }
        return 0
    }

    /**
     * Format the [AuthenticateAPI.Result] as a [String] which can be printed to standard out.
     */
    internal fun formatResult(result: AuthenticateAPI.Result) {
        if (result.percentage < 100) {
            println("No paths found.")
        }
        println(result.binding.toConsoleOut(result.targetAmount, WotCLI.dateFormat))
    }
}