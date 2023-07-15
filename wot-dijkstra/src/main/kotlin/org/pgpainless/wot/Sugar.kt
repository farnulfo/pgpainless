// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot

/**
 * Variant of [let] which takes an additional [predicate] and returns the result of applying
 * [block] iff [predicate] evaluates to true, otherwise it returns the value unchanged.
 *
 * @param predicate boolean
 * @param block function block that is applied to [this] iff [predicate] evaluates to true
 * @return the result of applying [block] to [this] iff [predicate] evaluates to true, [this] otherwise
 * @receiver [this]
 */
fun <T> T.letIf(predicate: T.() -> Boolean, block: T.() -> T): T =
        let {
            if (predicate(this))
                block(this)
            else
                this
        }

/**
 * Variant of [let] which takes an additional [condition] and returns the result of applying
 * [block] iff [condition] is true, otherwise it returns the value unchanged.
 *
 * @param condition boolean
 * @param block function block that is applied to [this] iff [condition] is true
 * @return the result of applying [block] to [this] iff [condition] is true, [this] otherwise
 * @receiver [this]
 */
fun <T> T.letIf(condition: Boolean, block: T.() -> T): T =
        let {
            if (condition)
                block(this)
            else
                this
        }

/**
 * Variant of [apply] which takes an additional [predicate] and only applies the [block]
 * iff [predicate] evaluates to true.
 *
 * @param predicate predicate on [this]
 * @param block function block that is applied to [this] iff [predicate] evaluates to true
 * @return the result of applying [block] to this iff [predicate] evaluates to true, otherwise [this] unchanged
 * @receiver [this]
 */
fun <T> T.applyIf(predicate: T.() -> Boolean, block: T.() -> Unit): T =
        apply {
            if (predicate(this))
                block(this)
        }

/**
 * Variant of [apply] which takes an additional [condition] and only applies the [block]
 * iff the [condition] is true.
 *
 * @param condition boolean
 * @param block function block that is applied to [this] iff [condition] is true
 * @return the result of applying [block] to this iff [condition] is true, otherwise [this] unchanged
 * @receiver [this]
 */
fun <T> T.applyIf(condition: Boolean, block: T.() -> Unit): T =
        apply {
            if (condition)
                block(this)
        }