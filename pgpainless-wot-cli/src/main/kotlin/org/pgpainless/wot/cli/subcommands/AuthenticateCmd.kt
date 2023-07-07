// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.api.AuthenticateAPI
import org.pgpainless.wot.cli.WotCLI
import org.pgpainless.wot.dijkstra.sq.Fingerprint
import org.pgpainless.wot.dijkstra.sq.Path
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

    private val dateFormat: SimpleDateFormat = SimpleDateFormat("yyyy-MM-dd")

    /**
     * Execute the command.
     * @return exit code
     */
    override fun call(): Int {
        val result = parent.api.authenticate(AuthenticateAPI.Arguments(
                Fingerprint(fingerprint), userId, email))
        print(formatResult(result))
        if (result.percentage < 100) {
            return -1
        }
        return 0
    }

    /**
     * Format the [AuthenticateAPI.Result] as a [String] which can be printed to standard out.
     */
    internal fun formatResult(result: AuthenticateAPI.Result): String {
        if (result.percentage < 100) {
            return "No paths found."
        }

        val sb = StringBuilder()
        sb.appendLine("[✓] ${result.fingerprint} ${result.userId}: fully authenticated (${result.percentage}%)")
        for ((pIndex, path: Path) in result.paths.paths.withIndex()) {
            sb.appendLine("  Path #${pIndex + 1} of ${result.paths.paths.size}, trust amount ${path.amount}:")
            for ((cIndex, certification) in path.certifications.withIndex()) {
                val issuerUserId = certification.issuer.userIds.keys.firstOrNull()?.let { " (\"${it}\")" } ?: ""
                when (cIndex) {
                    0 -> {
                        sb.appendLine("    ◯ ${certification.issuer.fingerprint}${issuerUserId}")
                    }
                    else -> {
                        sb.appendLine("    ├ ${certification.issuer.fingerprint}${issuerUserId}")
                    }
                }
                sb.appendLine("    │   certified the following binding on ${dateFormat.format(certification.creationTime)}")
            }
            sb.appendLine("    └ ${result.fingerprint} \"${result.userId}\"")
        }

        return sb.toString()
    }
}