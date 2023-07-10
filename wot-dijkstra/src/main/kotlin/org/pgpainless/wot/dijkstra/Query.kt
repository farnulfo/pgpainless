// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra

import org.pgpainless.wot.dijkstra.filter.*
import org.pgpainless.wot.network.*
import org.pgpainless.wot.query.Path
import org.pgpainless.wot.query.Paths
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.Date
import kotlin.math.min

// The amount of trust needed for a binding to be fully trusted.
private const val FULLY_TRUSTED = 120

// The usual amount of trust assigned to a partially trusted
// introducer.
//
// Normally, three partially trusted introducers are needed to
// authenticate a binding.  Thus, this is a third of `FULLY_TRUSTED`.
private const val PARTIALLY_TRUSTED = 40


/**
 * A path's cost.
 *
 * This is needed to do a Dijkstra.
 */
internal class Cost(
        // The path's length (i.e., the number of hops to the target).
        // *Less* is better (we prefer short paths).
        val length: Int,

        // The trust amount along this path.
        // More is better (we prefer paths with a high trust amount).
        val amount: Int,
) : Comparable<Cost> {

    // "Greater than" means: the path is preferable, that is:
    // - It requires a small number of hops (length)
    // - It has a high "trust amount"
    override fun compareTo(other: Cost) =
            compareValuesBy(this, other, { -it.length }, { it.amount })

}

// We perform a Dijkstra in reserve from the target towards the roots.
internal data class ForwardPointer(
        // If null, then the target.
        val next: EdgeComponent?
)

interface NetworkView {

    fun nodeByFpr(fpr: Fingerprint): Node?
    fun reverseBySignee(fpr: Fingerprint): List<Edge>?
    fun referenceTime(): ReferenceTime
}

class Query(
        private val network: NetworkView,
        private val roots: Roots,
        private val certificationNetwork: Boolean) {

    private val logger: Logger = LoggerFactory.getLogger(Query::class.java)

    /**
     * Authenticates the specified binding.
     *
     * Enough independent paths are gotten to satisfy `target_trust_amount`.
     *
     * A fully trusted authentication is 120. If you require that a binding
     * be double authenticated, you can specify 240.
     */
    fun authenticate(targetFpr: Fingerprint,
                     targetUserid: String,
                     targetTrustAmount: Int): Paths {

        logger.debug("Query.authenticate")
        logger.debug("Authenticating <{}, '{}'>", targetFpr, targetUserid)
        logger.debug("Roots ({}):", roots.size())
        logger.debug(roots.roots().withIndex()
                .joinToString("\n") { (i, r) -> "  $i: $r" })

        val paths = Paths()

        // This ChainFilter collects modifiers to the network over the course
        // of the calculation of this authentication.
        val filters = ChainFilter()

        if (certificationNetwork) {
            // We're building a certification network.
            // (Treat all certifications like delegations with infinite depth
            // and no regular expressions.)
            filters.add(TrustedIntroducerFilter())
        } else {
            // We're building a regular authentication network.

            // Model trust amounts of roots as a CapCertificateFilter
            // for roots that are not "FULLY_TRUSTED"
            if (roots.roots().any { it.amount != FULLY_TRUSTED }) {
                val caps = CapCertificateFilter()

                roots.roots().forEach {
                    if (it.amount != FULLY_TRUSTED) {
                        caps.cap(it.fingerprint, it.amount)
                    }
                }

                filters.add(caps)
            }
        }

        // Perform a (partial) run of the Ford Fulkerson algorithm.
        //
        // (The Ford Fulkerson algorithm finds a path, computes a residual
        // network by subtracting that path, and then loops until no paths
        // remain)


        // On iteration/looping:
        //
        // "Better mimic GnuPG's trust root semantics
        //
        //  If Alice considers Bob and Carol to be fully trusted, Alice has
        //  certified Bob, and Bob has certified Carol, then Carol should be
        //  considered a trust root, because she is certified by Bob, who is
        //  considered a trust root, because he is certified by Alice.
        //
        //  In other words, we need to iterate."
        //
        // https://gitlab.com/sequoia-pgp/sequoia-wot/-/commit/ff006688155aaa3ee0c14b88bef1a143b0ecae23
        var progress = true
        while (progress && paths.amount < targetTrustAmount) {
            progress = false

            val authPaths = backwardPropagate(targetFpr, targetUserid, filters)

            // The paths returned by backward_propagate may overlap.
            // So we only use one (picking one of the best, by trust and length).
            //
            // Then we subtract the path from the network and run backward_propagate
            // again, if we haven't yet reached 'targetTrustAmount'.
            val bestPath = roots.fingerprints()
                    .mapNotNull { authPaths[it] } // Only consider paths that start at a root.
                    .maxWithOrNull(compareBy(
                            // We want the *most* amount of trust,
                            { it.second }, // path amount
                            // but the *shortest* path.
                            { -it.first.length }, // -path.len
                            // Be predictable.  Break ties based on the fingerprint of the root.
                            { it.first.root.fingerprint })
                    )

            if (bestPath != null) {
                val (path, amount) = bestPath

                if (path.length == 1) {
                    // This path is a root.
                    //
                    // We've used 'amount' of trust from this root, so we'll suppress
                    // that amount from it.
                    val suppress = SuppressIssuerFilter()
                    suppress.suppressIssuer(path.root.fingerprint, amount)
                    filters.add(suppress)
                } else {
                    // We create a residual network by suppressing this path.
                    val suppress = SuppressCertificationFilter()
                    suppress.suppressPath(path, amount)
                    filters.add(suppress)
                }

                paths.add(path, amount)
                progress = true
            }
        }

        return paths
    }


    /**
     * Finds a path in the network from one or multiple `roots` that
     * authenticates the target binding.
     *
     * If `roots` is empty, authenticated paths starting from any node
     * are returned.
     *
     *
     * Does one backwards propagation run. By default, always with self-sig 'true'.
     * Repeats the call with 'false', if 'true' returns no results.
     *
     * Note: the algorithm in backwardPropagateInternal() prefers shorter paths
     * to longer paths. So the returned path(s) may not be optimal in terms of the amount of trust.
     * To compensate for this, the caller should run the algorithm again on
     * a residual network.
     *
     * FIXME: public for unit tests (undo!)
     */
    fun backwardPropagate(targetFpr: Fingerprint, targetUserid: String, filter: CertificationFilter): HashMap<Fingerprint, Pair<Path, Int>> {
        // XXX: this is an experiment, calculating both variants is possibly not the most efficient approach.

        // However, in terms of semantics, this function now simulates what would happen if
        // backwardPropagateInternal() were generalized to find both types of paths:

        // It would prefer shorter over longer paths, or higher trust amount - so this is what we do here.

        val a = backwardPropagateInternal(targetFpr, targetUserid, true, filter)
        val b = backwardPropagateInternal(targetFpr, targetUserid, false, filter)

        val c = HashMap<Fingerprint, Pair<Path, Int>>()

        val keys = a.keys.toMutableSet()
        keys.addAll(b.keys)

        for (fp in keys) {
            val x = a[fp]
            val y = b[fp]

            if (x != null && y != null) {
                // Pick the path we like better, first by length, then by amount
                println("x: $x")
                println("y: $y")

                if (y.first.length < x.first.length) { // prefer smaller length
                    println("XX found two for $fp! -> picking y by length")
                    c[fp] = y
                } else if (x.first.length < y.first.length) {
                    println("XX found two for $fp! -> picking x by length")
                    c[fp] = x
                } else {
                    // length is the same, pick by amount
                    if (y.second > x.second) { // prefer bigger amount
                        println("XX found two for $fp! -> picking y by amount")
                        c[fp] = y
                    } else {
                        println("XX found two for $fp! -> picking x by amount")
                        c[fp] = x
                    }
                }
            } else if (x != null) {
                println("XX found one for $fp, in x")
                c[fp] = x
            } else if (y != null) {
                println("XX found one for $fp, in y")
                c[fp] = y
            }
        }

        return c
    }

    /**
     * Implements the algorithm outlined in:
     * https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/spec/sequoia-wot.md#implementation-strategy
     *
     *
     * `selfSigned` picks between two variants of this algorithm. Each of the
     * modes finds a distinct subset of authenticated paths:
     *
     * - If `true`, this function only finds paths that end in a
     * self-certification, and only if the target node is
     * a trusted introducer.
     *
     * - If `false`, this function only finds paths that don't use
     * a self-certification as the last edge.
     */
    private fun backwardPropagateInternal(targetFpr: Fingerprint,
                                          targetUserid: String,
                                          selfSigned: Boolean,
                                          filter: CertificationFilter)
            : HashMap<Fingerprint, Pair<Path, Int>> {

        logger.debug("Query.backward_propagate")

        logger.debug("Roots (${roots.size()}):\n{}",
                roots.roots().withIndex().joinToString("\n") { (i, r) ->
                    val fpr = r.fingerprint
                    network.nodeByFpr(fpr)?.let { "  {$i}. {$it}" } ?: "  {$i}. {$fpr} (not found)"
                })

        logger.debug("target: {}, {}", targetFpr, targetUserid)
        logger.debug("self signed: {}", selfSigned)

        // If the node is not in the network, we're done.
        val target = network.nodeByFpr(targetFpr) ?: return hashMapOf()

        // Make sure the target is valid (not expired and not revoked
        // at the reference time).
        if ((target.expirationTime != null) &&
                (target.expirationTime <= network.referenceTime().timestamp)) {
            logger.debug("{}: Target certificate is expired at reference time.", targetFpr)
            return hashMapOf()
        }

        if (target.revocationState.isEffective(network.referenceTime())) {
            logger.debug("{}: Target certificate is revoked at reference time.", targetFpr)
            return hashMapOf()
        }

        // Recall: the target doesn't need to have self-signed the
        // User ID to authenticate the User ID.  But if the target has
        // revoked it, then it can't be authenticated.
        val targetUa: RevocationState? = target.userIds[targetUserid]
        targetUa?.let {
            if (it.isEffective(network.referenceTime())) {
                logger.debug("{}: Target user id is revoked at reference time.", targetFpr)
                return hashMapOf()
            }
        }

        // Dijkstra.
        val bestNextNode: HashMap<Fingerprint, ForwardPointer> = HashMap()
        val queue: PairPriorityQueue<Fingerprint, Cost> = PairPriorityQueue()

        fun fpCost(fp0: ForwardPointer): Cost {
            var fp = fp0

            var amount = 120
            var length: Int = if (selfSigned) 1 else 0

            while (fp.next != null) {
                val ec: EdgeComponent = fp.next!! // FIXME

                val a = ec.trustAmount
                val d = ec.trustDepth

                val value = FilterValues(d, a, null)

                val r = filter.cost(ec, value, true)
                assert(r) { "cost function returned different result, but must be constant!" }

                amount = min(value.amount, amount)
                length += 1
                fp = bestNextNode[ec.target.fingerprint]!!
            }

            return Cost(length, amount)
        }

        if (selfSigned) {
            // If the target is a trusted introducer and has self-signed
            // the User ID, then also consider that path.
            if (targetUa != null) {
                logger.debug("Target User ID is self signed.")

                val cost = Cost(1, 120)
                queue.insert(targetFpr, cost)
                bestNextNode[targetFpr] = ForwardPointer(null)
            } else {
                logger.debug("Target User ID is not self-signed, but that is required.")
                return hashMapOf()
            }
        } else {
            val cost = Cost(0, 120)
            queue.insert(targetFpr, cost)
            bestNextNode[targetFpr] = ForwardPointer(null)
        }


        // Iterate over each node in the priority queue.
        while (true) {
            val signeeFpr = queue.pop()?.first ?: break

            val it = roots.get(signeeFpr)
            if ((it != null) && (it.amount >= FULLY_TRUSTED)) {
                // XXX: Technically, we could stop if the root's trust
                // amount is at least the required trust amount.
                // Since we don't know it, and the maximum is
                // `FULLY_TRUSTED`, we use that.
                logger.debug("Skipping fully trust root: {}.", it.fingerprint)

                continue
            }

            val signee = network.nodeByFpr(signeeFpr)!! // already looked up

            // Get the signee's current forward pointer.
            //
            // We need to clone this, because we want to manipulate
            // 'distance' and we can't do that if there is a reference
            // to something in it.
            val signeeFp: ForwardPointer = bestNextNode[signeeFpr]!!
            val signeeFpCost = fpCost(signeeFp)

            logger.debug("{}'s forward pointer: {}", signeeFpr, signeeFp.next?.target)

            // Get signeeFp

            // Not limiting by required_depth, because 'network' doesn't expose an interface for this
            val certificationSets: List<Edge> =
                    network.reverseBySignee(signeeFpr).orEmpty() // "certifications_of"

            if (certificationSets.isEmpty()) {
                // Nothing certified it.  The path is a dead end.
                logger.debug("{} was not certified, dead end", signeeFpr)
                continue
            }

            logger.debug("Visiting {} ({}), certified {} times",
                    signee.fingerprint,
                    signee.toString(),
                    certificationSets.size)

            for (certification in certificationSets
                    .map { cs ->
                        cs.components
                                .map { it.value }.flatten()
                    }.flatten()) {

                val issuerFpr = certification.issuer.fingerprint

                val fv = FilterValues(certification.trustDepth,
                        certification.trustAmount,
                        certification.regexes)

                if (!filter.cost(certification, fv,
                                false)) {
                    logger.debug("  Cost function says to skip certification by {}", certification.issuer)
                    continue
                }

                logger.debug("  Considering certification by: {}, depth: {} (of {}), amount: {} (of {}), regexes: {}",
                        certification.issuer,
                        fv.depth,
                        certification.trustDepth,
                        fv.amount,
                        certification.trustAmount,
                        fv.regexps)


                if (fv.amount == 0) {
                    logger.debug("    Certification amount is 0, skipping")
                    continue
                }

                if (!selfSigned
                        && signeeFpr == targetFpr
                        && certification.userId != targetUserid) {
                    assert(signeeFp.next == null)

                    logger.debug("    Certification certifies target, but for the wrong user id (want: {}, got: {})",
                            targetUserid, certification.userId)

                    continue
                }

                if (fv.depth < Depth.auto(signeeFpCost.length)) {
                    logger.debug("    Certification does not have enough depth ({}, needed: {}), skipping", fv.depth, signeeFpCost.length)
                    continue
                }

                val re = fv.regexps
                if ((re != null) && !re.matches(targetUserid)) {
                    logger.debug("  Certification's re does not match target User ID, skipping.")
                    continue
                }

                val proposedFp: ForwardPointer = ForwardPointer(certification)

                val proposedFpCost = Cost(signeeFpCost.length + 1,
                        min(fv.amount, signeeFpCost.amount))

                logger.debug("  Forward pointer for {}:", certification.issuer)

                val pn = proposedFp.next // cache value for debug output
                logger.debug("    Proposed: {}, amount: {}, depth: {}",
                        pn?.target ?: "target", proposedFpCost.amount, proposedFpCost.length)

                // distance.entry takes a mutable ref, so we can't
                // compute the current fp's cost in the next block.
                val currentFpCost: Cost? = bestNextNode[issuerFpr]?.let { fpCost(it) }

                when (val currentFp = bestNextNode[issuerFpr]) {
                    null -> {
                        // We haven't seen this node before.

                        logger.debug("    Current: None")
                        logger.debug("  Setting {}'s forward pointer to {}", certification.issuer, signee)
                        logger.debug("  Queuing {}", certification.issuer)

                        queue.insert(issuerFpr, proposedFpCost)
                        bestNextNode[issuerFpr] = proposedFp
                    }

                    else -> {
                        // We've visited this node in the past.  Now
                        // we need to determine whether using
                        // certification and following the proposed
                        // path is better than the current path.

                        val currentFpCost = currentFpCost!! // shadow the variable

                        // If the proposed Fp is better, replace it in the forward pointer list
                        if (proposedFpCost > currentFpCost) {
                            logger.debug("    Preferring proposed: current {}, proposed {}", currentFpCost, proposedFpCost)
                            bestNextNode[issuerFpr] = proposedFp
                        }
                    }
                }
            }
        }

        // Follow the forward pointers and reconstruct the paths.
        val authRpaths: HashMap<Fingerprint, Pair<Path, Int>> = hashMapOf()

        for ((issuerFpr, fp) in bestNextNode.entries) {
            var fp = fp // Shadow for write access

            // If roots were specified, then only return the optimal
            // paths from the roots.
            if (roots.size() > 0 && !roots.isRoot(issuerFpr)) {
                continue
            }

            val c = fp.next
            val issuer =
                    if (c != null) {
                        c.issuer
                    } else {

                        // The target.
                        if (!selfSigned) {
                            continue
                        }

                        // Apply any policy to the self certification.
                        //
                        // XXX: Self-signatures should be first class and not
                        // synthesized like this on the fly.
                        val selfsig = EdgeComponent(
                                target, target, targetUserid,

                                // FIXME! Use userid binding signature by default, reference time only as fallback:

                                // target_ua.map(|ua| ua.binding_signature_creation_time())
                                //    .unwrap_or(self.network().reference_time()))

                                network.referenceTime().timestamp,

                                null, true, 120, Depth.limited(0), RegexSet.wildcard()
                        )

                        val fv = FilterValues(Depth.auto(0), 120, null)
                        if (filter.cost(selfsig, fv, true)) {
                            logger.debug("Policy on selfsig => amount: {}", fv.amount)

                            if (fv.amount == 0) {
                                continue
                            }
                        } else {
                            logger.debug("Policy says to ignore selfsig")
                            continue
                        }

                        val p = Path(target)
                        logger.debug("Authenticated <{}, {}>:\n{}", targetFpr, targetUserid, p)

                        authRpaths[issuerFpr] = Pair(p, fv.amount)

                        continue
                    }

            logger.debug("Recovering path starting at {}", network.nodeByFpr(issuerFpr))

            var amount = 120

            // nodes[0] is the root; nodes[nodes.len() - 1] is the target.
            val nodes: MutableList<EdgeComponent> = mutableListOf()
            while (true) {
                val ec = fp.next ?: break

                logger.debug("  {}", fp)

                val fv = FilterValues(ec.trustDepth, ec.trustAmount, null)

                val r = filter.cost(ec, fv, true)

                assert(r) {
                    "cost function returned different result, but must be constant !"
                }
                amount = min(fv.amount, amount)

                nodes.add(ec)
                fp = bestNextNode[ec.target.fingerprint]!! // FIXME !!
            }

            if (selfSigned) {
                val tail = nodes.last()
                if (tail.userId != targetUserid) {
                    /// XXX: don't synthesize selfsigs
                    val selfsig = EdgeComponent(target, target, targetUserid, Date(),
                            null, true, 120, Depth.limited(0), RegexSet.wildcard())
                    nodes.add(selfsig)
                }
            }

            logger.debug("  {}", fp)

            logger.debug("\nShortest path from {} to <{} <-> {}>:\n  {}",
                    issuer.fingerprint,
                    targetUserid, targetFpr,
                    nodes.withIndex().joinToString("\n  ") { (i, certification) ->
                        "$i: $certification"
                    })

            assert(nodes.size > 0)

            val p = Path(issuer)
            for (n in nodes.iterator()) {
                p.append(n)
            }
            logger.debug("Authenticated <{}, {}>:\n{}", targetFpr, targetUserid, p)

            authRpaths[issuerFpr] = Pair(p, amount)
        }

        //        if TRACE {
        //            t!("auth_rpaths:")
        //            let mut v: Vec<_> = auth_rpaths.iter().collect()
        //            v.sort_by(|(fpr_a, _), (fpr_b, _)| {
        //            let userid_a = self.network()
        //                    .lookup_synopsis_by_fpr(*fpr_a).expect("already looked up")
        //                    .primary_userid().map(|userid| {
        //                String::from_utf8_lossy(userid.value()).into_owned()
        //            }).unwrap_or("".into())
        //            let userid_b = self.network()
        //                    .lookup_synopsis_by_fpr(*fpr_b).expect("already looked up")
        //                    .primary_userid().map(|userid| {
        //                String::from_utf8_lossy(userid.value()).into_owned()
        //            }).unwrap_or("".into())
        //
        //            userid_a.cmp(&userid_b).
        //            then(fpr_a.cmp(&fpr_b))
        //        })
        //            for (fpr, (path, amount)) in v {
        //            let userid = self.network()
        //                    .lookup_synopsis_by_fpr(fpr).expect("already looked up")
        //                    .primary_userid().map(|userid| {
        //                String::from_utf8_lossy(userid.value()).into_owned()
        //            })
        //            .unwrap_or("<missing User ID>".into())
        //            t!("  <{}, {}>: {}",
        //            fpr, userid,
        //            format!("{} trust amount (max: {}), {} edges",
        //            amount, path.amount(),
        //            path.len() - 1))
        //        }
        //        }

        return authRpaths
    }
}
