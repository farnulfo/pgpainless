// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.pgpainless.wot.network.EdgeComponent

/**
 * Pointer type for Dijsktra's algorithm.
 * This encapsulates the outgoing edge (there may be multiple edges between a source and a target node).
 */
internal data class ForwardPointer(
        // If null, then the node is itself the target.
        val next: EdgeComponent?
)