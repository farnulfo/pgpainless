// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.suite.harness

import org.sequoia_pgp.wot.suite.ExecutionCallback
import org.sequoia_pgp.wot.suite.SimpleTestCase

/**
 * Abstract class to produce [SimpleTestCase.ExecutionCallback] instances for WOT CLI implementations.
 */
abstract class Harness {

    /**
     * Return a [SimpleTestCase.ExecutionCallback] which executes a [SimpleTestCase] using a custom WOT implementation.
     */
    abstract fun runner(): ExecutionCallback
}