package org.pgpainless.wot.query

import org.pgpainless.wot.network.EdgeComponent

/**
 * Pointer type for Dijsktra's algorithm.
 * This encapsulates the outgoing edge (there may be multiple edges between a source and a target node).
 */
internal data class ForwardPointer(
        // If null, then the node is itself the target.
        val next: EdgeComponent?
)