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
        val api = parent.api
        val result = api.identify(IdentifyAPI.Arguments(Fingerprint(fingerprint)))
        println(formatResult(result))
        return exitCode(result)
    }

    fun formatResult(result: IdentifyAPI.Result): String {
        if (result.target == null || result.paths.isEmpty()) {
            return "No paths found."
        }

        return buildString {
            result.paths.keys.forEach { userId ->
                val target = result.target!!
                appendLine("[✓] ${target.fingerprint} $userId: fully authenticated: (${result.percentage(userId)}%)")
                result.paths[userId]!!.paths.forEach {path ->
                    val root = path.root
                    val userIdString = if (root.userIds.isEmpty()) "" else " (${root.userIds.keys.first()})"
                    appendLine("  ◯ ${root.fingerprint}$userIdString")
                    path.certifications.forEachIndexed { index, edge ->
                        appendLine("  │   certified the following binding on ${WotCLI.dateFormat.format(edge.creationTime)}")
                        append("  ").append(if (index == path.certifications.lastIndex) "└" else "├")
                                .appendLine(" ${edge.target.fingerprint} \"${edge.userId}\"")
                    }
                }
            }
        }
    }

    fun exitCode(result: IdentifyAPI.Result): Int {
        return if(result.paths.isEmpty()) -1 else 0
    }

}