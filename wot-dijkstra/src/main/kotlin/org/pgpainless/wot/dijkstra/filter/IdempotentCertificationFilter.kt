// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.filter

/**
 * A no-op filter.
 *
 * This filter passes certifications through as is.
 */
class IdempotentCertificationFilter : CertificationFilter