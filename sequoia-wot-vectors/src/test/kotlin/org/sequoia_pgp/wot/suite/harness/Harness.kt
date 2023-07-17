// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite.harness

import org.sequoia_pgp.wot.suite.TestCase

/**
 * Abstract class to produce [TestCase.ExecutionCallback] instances for WOT CLI implementations.
 */
abstract class Harness {

    /**
     * Return a [TestCase.ExecutionCallback] which executes a [TestCase] using a custom WOT implementation.
     */
    abstract fun runner(): TestCase.ExecutionCallback
}