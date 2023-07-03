// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.cli.subcommands

import org.pgpainless.wot.cli.WotCLI
import picocli.CommandLine
import picocli.CommandLine.Command
import java.util.concurrent.Callable

@Command(name = "list", description = ["Find all bindings that can be authenticated for all certificates."])
class ListCmd: Callable<Int> {

    @CommandLine.ParentCommand
    lateinit var parent: WotCLI

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