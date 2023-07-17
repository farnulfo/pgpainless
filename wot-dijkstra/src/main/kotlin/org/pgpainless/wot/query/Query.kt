package org.pgpainless.wot.query

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.Node
import org.pgpainless.wot.network.Roots
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.math.max

// The trust amount that is considered "fully trusted"
private const val FULLY_TRUSTED = 120

class Query(private val rawNetwork: Network,
            private val roots: Roots,
            private val certificationNetwork: Boolean) {

    private val logger: Logger = LoggerFactory.getLogger(Query::class.java)

    /**
     * Authenticate the binding "targetFpr <-> targetUserid".
     *
     * Performs an OpenPGP "Web of Trust" query, following the semantics and approach described in
     * https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/spec/sequoia-wot.md
     *
     * Searches for enough paths to satisfy `targetTrustAmount`, if available.
     */
    fun authenticate(targetFpr: Fingerprint, targetUserid: String, targetTrustAmount: Int): Paths {
        logger.debug("Authenticating <{}, '{}'>\nRoots: {}", targetFpr, targetUserid, roots)

        // Wrap the raw Network in a WotNetwork
        val network = WotNetwork(rawNetwork, certificationNetwork)
        // FIXME: add roots to the WotNetwork? -> handle their trust amounts from there (-> drop suppressIssuer?)

        if (!certificationNetwork) {
            // We're building a regular authentication network.
            // Set trust amount cap for any root that is not FULLY_TRUSTED
            roots.roots()
                    .filter { it.amount != FULLY_TRUSTED }
                    .forEach { network.capCertificate(it.fingerprint, it.amount) }

            // FIXME: If A is a fully trusted root, and B is a root at trust amount 40, should B's amount in
            // the path A -> B -> C be capped?
            //
            // Theory: The cap should only be in effect for paths in which B serves as a root.
            //  -> Make a test case for this, and fix it. (How?)
            // (Maybe the order in which paths are usually found will shadow this problem most of the time?)
        }

        val paths = Paths()

        // Perform a (partial, until the targetTrustAmount is reached) run of the Ford-Fulkerson algorithm
        // (https://en.wikipedia.org/wiki/Ford%E2%80%93Fulkerson_algorithm):
        //
        // Find a path, subtract that path from the network, then loop and search for more paths, if any.
        while (paths.amount < targetTrustAmount) {
            val authPaths = backwardPropagate(network, targetFpr, targetUserid)

            // Pick one of the paths returned by backwardPropagate(), first by trust amount, then by length.
            // We subtract that path from the network and search again, if we haven't yet reached 'targetTrustAmount'.
            val bestPath = roots.fingerprints()
                    .mapNotNull { authPaths[it] } // Only consider paths that start at a root.
                    .maxWithOrNull(compareBy(
                            { it.second }, // We want paths with the *largest* trust amount,
                            { -it.first.length }, // and of these, the *shortest* path.
                            { it.first.root.fingerprint } // Break ties based on the fingerprint of the root.
                    ))

            if (bestPath != null) {
                val (path, amount) = bestPath
                assert(path.length > 1) // We don't support paths without an edge!

                network.suppressPath(path, amount) // Subtract the path from the residual network
                paths.add(path, amount) // Add the path to the set of results
            } else {
                // We made no progress in this iteration, there are no more paths to be found. We're done.
                break
            }
        }

        return paths
    }

    // FIXME: This should not be public, but is currently needed for the `BackPropagationTest` suite.
    fun backwardPropagate(targetFpr: Fingerprint, targetUserid: String): HashMap<Fingerprint, Pair<Path, Int>> {
        val network = WotNetwork(rawNetwork, false) // these tests want authentication networks
        return backwardPropagate(network, targetFpr, targetUserid)
    }

    /**
     * Finds a path in the network from one or multiple `roots` that
     * authenticates the target binding.
     *
     * If `roots` is empty, authenticated paths starting from any node
     * are returned.
     */
    private fun backwardPropagate(network: WotNetwork, targetFpr: Fingerprint, targetUserid: String):
            HashMap<Fingerprint, Pair<Path, Int>> {
        logger.debug("Query.backwardPropagate <{}, '{}'>\nRoots: {}", targetFpr, targetUserid, roots)

        // If the Network tells us we can't use this node as a target, return early
        val target = network.isValidTarget(targetFpr, targetUserid) ?: return HashMap()


        // Perform Dijkstra's shortest path algorithm using a priority queue.
        // https://en.wikipedia.org/wiki/Dijkstra's_algorithm#Using_a_priority_queue

        // We are processing the OpenPGP certification graph in the backwards direction
        // (working from the target binding to the trust roots).
        // Note: The first step in the (reverse) paths we consider is always a certification of a User ID binding.
        // All other steps must be delegations with the minimum depth appropriate to the path's length.

        val prev: HashMap<Fingerprint, ForwardPointer> = HashMap()
        val dist: HashMap<Fingerprint, Cost> = HashMap()

        val queue: PairPriorityQueue<Fingerprint, Cost> = PairPriorityQueue()

        // Does a self-sig for the target exist?
        val selfSig = network.getSelfSig(targetFpr, targetUserid)
        val selfSigAmount = if (selfSig != null) network.getEffectiveTrustAmount(selfSig) else 0

        if (selfSig != null && selfSigAmount > 0) {
            // The first step of the (backwards-facing) path:
            // Arriving indirectly to the targetNode's User ID, via a delegation plus a self-signed binding
            val cost = Cost(1, selfSigAmount)
            prev[targetFpr] = ForwardPointer(selfSig)
            dist[targetFpr] = cost

            queue.insertOrUpdate(targetFpr, cost)
        } else {
            // The first step of the (backwards-facing) path:
            // We will arrive directly at the targetNode's relevant User ID, via a third party certification
            val cost = Cost(0, FULLY_TRUSTED)
            prev[targetFpr] = ForwardPointer(null)
            dist[targetFpr] = cost

            queue.insertOrUpdate(targetFpr, cost)
        }

        // Process the priority queue until it is empty.
        while (true) {
            // To be safe, we're not using the cost from the priority queue (which is available in `pop().second`).
            // It could have been updated in the meantime (?)
            val signeeFpr = queue.pop()?.first ?: break

            logger.debug("Processing signee {}", signeeFpr)

            val root = roots.get(signeeFpr)
            if ((root != null) && (root.amount >= FULLY_TRUSTED)) {
                logger.debug("  Skipping signee that is a fully trusted root")
                continue
            }

            val signee = network.nodeByFpr(signeeFpr)!! // We expect that the signee exists in the Network

            // Get the signee's current forward pointer (the edge that currently points at the signee)
            val signeeFp: ForwardPointer = prev[signeeFpr]!!
            // ... and the current cost/"distance" from the signee to the target
            val signeeCost = dist[signeeFpr]!!

            logger.debug("  Current forward pointer: {}", signeeFp.next?.target)
            logger.debug("  Current cost to target: {}", signeeCost)

            // Get certifications that point at signeeFpr
            // (with the necessary minimum depth, and matching the targetUserid to the certification regex, if any)

            // We are considering two different possibilities: extending the existing path, or effectively
            // *replacing* the existing path. The latter happens if our path currently consists of a self-sig,
            // but we're "replacing" that path with a third party sig.

            // XX: ask for "depth=n-1" to be able to replace a terminating self-sig with a depth 0 third party sig.
            // This requires additional checking below. Can this be simplified?
            val curMinLen = max(0, signeeCost.length - 1)

            val ecs = network.certificationsForSignee(signeeFpr, targetUserid, curMinLen)

            logger.debug("  Checking {} certifications for {}:", ecs.size, signee.toString())

            for (ec in ecs) {
                logger.debug("    Certification by {}", ec.issuer.fingerprint)

                val amount = network.getEffectiveTrustAmount(ec)
                if (amount == 0) {
                    logger.debug("      Skipping (effective trust amount is 0)")
                    continue
                }

                if (signeeFpr == targetFpr && ec.userId != targetUserid
                        // Matching User ID only matters for the last hop
                        && signeeCost.length == 0) {
                    logger.debug("      Certification is for the wrong user id ({})", ec.userId)
                    continue
                }

                val altCost = if (ec.userId == targetUserid) {
                    // This path replaces a direct signature
                    Cost(1, amount)
                } else {
                    // XX: temp hack, see above
                    if (ec.trustDepth < signeeCost.length) {
                        logger.debug("      Certification does not allow enough depth ({}, needed: {}), skipping",
                                ec.trustDepth, signeeCost.length)
                        continue
                    }

                    signeeCost.extendBy(amount)
                }

                logger.debug("      Cost to target via {}: {}", ec.target.fingerprint, altCost)

                val issuerFpr = ec.issuer.fingerprint
                val currentCost: Cost? = dist[issuerFpr]

                // If we haven't visited this node before, or the new cost is preferable, store or update pointer+cost
                if (currentCost == null || altCost < currentCost) {
                    logger.debug("      Setting forward pointer for {}: {}", ec.issuer, ec.target)

                    if (currentCost != null)
                        logger.debug("        (Replaces previous path with cost {})", currentCost)

                    prev[issuerFpr] = ForwardPointer(ec)
                    dist[issuerFpr] = altCost
                }

                if (currentCost == null) {
                    // We haven't seen this node before -> queue it for processing
                    logger.debug("      Queuing node {}", ec.issuer)
                    queue.insertOrUpdate(issuerFpr, altCost)
                }
            }
        }

        return reconstructPaths(network, targetUserid, prev, target, dist)
    }

    private fun reconstructPaths(network: WotNetwork, targetUserid: String, bestNextNode: HashMap<Fingerprint, ForwardPointer>, target: Node, dist: HashMap<Fingerprint, Cost>): HashMap<Fingerprint, Pair<Path, Int>> {
        // Follow the forward pointers and reconstruct the paths.
        val paths: HashMap<Fingerprint, Pair<Path, Int>> = HashMap()

        bestNextNode.entries
                // If roots were specified, only reconstruct paths for roots
                .filter { roots.roots().isEmpty() || roots.isRoot(it.key) }
                // Don't consider nodes that specify no "next" edge
                .filter { it.value.next != null }
                .forEach { (issuerFpr, fp) ->
                    // Next is guaranteed to be non-null by the filter above
                    val issuer = fp.next!!.issuer

                    logger.trace("Recovering path starting at {}", network.nodeByFpr(issuerFpr))
                    val path = assemblePath(target, targetUserid, issuer, bestNextNode)
                    val amount = dist[issuer.fingerprint]!!.amount

                    logger.debug("Authenticated <{}, {}>:\n{}", target.fingerprint, targetUserid, path)

                    paths[issuerFpr] = Pair(path, amount)
                }

        return paths
    }

    private fun assemblePath(target: Node, targetUserid: String,
                             issuer: Node, bestNextNode: HashMap<Fingerprint, ForwardPointer>): Path {
        var fp = bestNextNode[issuer.fingerprint]!!

        // Path starts at the root (issuer); the last edge points to the target.
        val p = Path(issuer)

        while (true) {
            val ec = fp.next ?: break
            p.append(ec)

            if (ec.userId == targetUserid) {
                // We've arrived (the target node may have an extra self-sig forward pointer to itself, but we don't
                // want to collect that edge).
                break
            }

            fp = bestNextNode[ec.target.fingerprint]!!
        }

        assert(p.certifications.isNotEmpty())

        logger.trace("\nAssembled path from {} to <{} <-> {}>:\n  {}",
                issuer.fingerprint, targetUserid, target.fingerprint,
                p.certifications.withIndex().joinToString("\n  ") { (i, c) -> "$i: $c" })

        return p
    }
}