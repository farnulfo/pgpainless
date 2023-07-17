package org.sequoia_pgp.wot.suite

import org.sequoia_pgp.wot.vectors.ArtifactVectors

interface ExecutionCallback {
    fun execute(vectors: ArtifactVectors, arguments: Array<String>): Pair<String, Int>
}