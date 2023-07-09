// SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer@name>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.query

import org.pgpainless.wot.network.*
import org.pgpainless.wot.query.filter.*
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
        // The path's depth (i.e., the number of hops to the target).
        // *Less* is better (we prefer short paths).
        val depth: Int,

        // The trust amount along this path.
        // More is better (we prefer paths with a high trust amount).
        val amount: Int,
) : Comparable<Cost> {

    // "Greater than" means: the path is preferable, that is:
    // - It requires a small number of hops ("depth")
    // - It has a high "trust amount"
    override fun compareTo(other: Cost) =
            compareValuesBy(this, other, { -it.depth }, { it.amount })

}

// We perform a Dijkstra in reserve from the target towards the roots.
internal data class ForwardPointer(
        // If null, then the target.
        val next: Edge?
)

class Query(
        private val network: Network,
        private val roots: Roots,
        private val certificationNetwork: Boolean) {

    private val logger: Logger = LoggerFactory.getLogger(Query::class.java)

    /**
     * Authenticates the specified binding.
     *
     * Enough independent paths are gotten to satisfy
     * `target_trust_amount`.  A fully trusted authentication is 120.
     * If you require that a binding be double authenticated, you can
     * specify 240.
     */
    fun authenticate(targetUserid: String, targetFpr: Fingerprint,
                     targetTrustAmount: Int): Paths {

        logger.debug("Query.authenticate")
        logger.debug("Authenticating <{}, '{}'>", targetFpr, targetUserid)
        logger.debug("Roots ({}):", roots.size())
        logger.debug(roots.roots().withIndex()
                .joinToString("\n") { (i, r) -> "  $i: $r" })

        val paths = Paths()

        val filter = ChainFilter(listOf<CertificationFilter>().toMutableList());
        if (this.certificationNetwork) {
            // We're building a certification network: treat all
            // certifications like tsigs with infinite depth and no
            // regular expressions.
            filter.filters.add(TrustedIntroducerFilter());
        } else {

            if (roots.roots().any { it.amount != FULLY_TRUSTED }) {
                val caps = CapCertificateFilter();
                for (r in roots.roots()) {
                    val amount = r.amount
                    if (amount != FULLY_TRUSTED) {
                        caps.cap(r.fingerprint, amount);
                    }
                }
                filter.filters.add(caps);
            }
        }

        var progress = true;
        run {
            while (progress && paths.amount < targetTrustAmount) {
                progress = false;

                for (selfSigned in listOf(true, false)) {
                    val authPaths: HashMap<Fingerprint, Pair<Path, Int>> =
                            backwardPropagate(targetFpr, targetUserid, selfSigned, filter);

                    // Note: the paths returned by backward_propagate may
                    // overlap.  As such, we can only take one.  (Or we need
                    // to subtract any overlap.  But that is fragile.)  Then
                    // we subtract the path from the network and run
                    // backward_propagate again, if necessary.
                    roots.fingerprints().mapNotNull {
                        // Get the paths that start at the roots.
                        authPaths[it]
                    }
                            .maxWithOrNull(compareBy(
                                    // We want the *most* amount of trust,
                                    { it.second }, // path amount
                                    // but the *shortest* path.
                                    { -it.first.length }, // -path.len
                                    // Be predictable.  Break ties based on the fingerprint of the root.
                                    { it.first.root.fingerprint })
                            )
                            .let {
                                it?.let { (path, pathAmount) ->
                                    if (path.length == 1) {
                                        // It's a root.
                                        val suppressFilter = SuppressIssuerFilter()
                                        suppressFilter.suppressIssuer(path.root.fingerprint, pathAmount)
                                        filter.filters.add(suppressFilter)
                                    } else {
                                        // Add the path to the filter to create a residual
                                        // network without this path.
                                        val suppressFilter = SuppressCertificationFilter()

                                        suppressFilter.suppressPath(path, pathAmount)
                                        filter.filters.add(suppressFilter)
                                    }

                                    paths.add(path, pathAmount);
                                    progress = true;

                                    // Prefer paths where the target User ID is self-
                                    // signed as long as possible.
                                    return@run
                                }
                            }

                }
            }
        }

        return paths
    }

    /// Performs backward propagation from a binding towards all other
    /// nodes.
    ///
    /// If there is a path in the network from a node to the target,
    /// this algorithm will find it.  However, because it prefers
    /// shorter paths to longer paths, the path may not be optimal in
    /// terms of the amount of trust.
    ///
    /// # Return Value
    ///
    /// This function returns a hash from certificate fingerprints to
    /// paths to the target.
    ///
    /// If `roots` is specified, then only the best path from each
    /// root to the target is returned.  If `roots` is empty, then the
    /// best path from each certificates to the target is returned.
    ///
    /// # Algorithm
    ///
    /// This algorithm reverses the edgeSet in the network and then
    /// executes a variant of [Dijkstra's shortest path algorithm].
    /// The algorithm sets the initial node to be the target and works
    /// outwards.  Consider the following network:
    ///
    /// ```text
    ///          .--> C ... v
    /// ... --> A           target
    ///          `--> D ... ^
    /// ```
    ///
    /// When visiting a certificate (say, `C`), the algorithm
    /// considers each certification on it (`A -> C`).  If prepending
    /// to the current path suffix (`C ... target`) results in a valid
    /// path suffix (`A - C ... target`), and the path suffix is
    /// better than the issuer's current path suffix (say `A - D
    /// ... target'), we update the issuer's forward pointer to use
    /// the new path suffix.
    ///
    ///   [Dijkstra's shortest path algorithm]: https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
    ///
    /// A certification is valid if it has any regular expressions and
    /// they match the target User ID.  Further, the certification's
    /// depth must be sufficient for the current path suffix.  If a
    /// certification certifies the target, then it must certify the
    /// target User ID.
    ///
    /// When comparing two forward pointers, the one with the shorter
    /// path is preferred.  If the two forward pointers have the same
    /// trust amount, then the one with the larger trust amount is
    /// preferred.
    ///
    /// # Examples
    ///
    /// Consider the following network:
    ///
    /// ```text
    ///                          120/255
    ///                        C         D
    ///                      _ o ------> o
    ///             120/255  /|            \  120/0
    ///                     /              _\|
    ///  o --------------> o --------------> o
    ///  A     100/2       B      30/0       E
    /// ```
    ///
    /// The tuples stand for the trust amount and the trust depth
    /// parameters.  So 120/255 means the trust amount is 120 and the
    /// trust depth is 255.  (In this case, both are maximal.)
    ///
    /// Let us assume that we want to authenticate E, and A is our only
    /// trust root.  Using backward propagation, we start at the
    /// target, E, and consider each certification made on E: D-E and
    /// B-E.
    ///
    /// Say we start with D-E (the order doesn't matter).  Since D
    /// doesn't yet have a forward pointer, we set its forward pointer
    /// to E and add D to the queue.  Then we consider B-E.  Since B
    /// doesn't yet have a forward pointer, we set its forward pointer
    /// to E, and we add B to the queue.
    ///
    /// ```text
    /// queue = [ D, B ];
    /// forward_pointers = [ (B -> E), (D -> E) ];
    /// ```
    ///
    /// Next we pop the certificate with the best path suffix from the
    /// queue.  Because B and D's provisional paths are the same
    /// length (1), we compare the amount of trust along each path.
    /// D's amount of trust is 120 whereas B's is only 30.  So, we pop
    /// D.
    ///
    /// D is only certified by C.  Looking at C, we see that it
    /// doesn't yet have a forward pointer so we set its forward
    /// pointer to D, and we add C to the queue.
    ///
    /// ```text
    /// queue = [ B, C ];
    /// forward_pointers = [ (B -> E), (C -> D), (D -> E) ];
    /// ```
    ///
    /// The queue now contains B and C.  We prefer B, because its path
    /// is shorter (1 vs 2).
    ///
    /// B is certified by A.  Since A's forward pointer is empty, we
    /// set it to point to B and add it to the queue.
    ///
    /// ```text
    /// queue = [ C, A ];
    /// forward_pointers = [ (A -> B), (B -> E), (C-> D), (D -> E) ];
    /// ```
    ///
    /// We now pop C from the queue: the paths starting at A and C
    /// have the same path length, but the trust amount for the
    /// current path starting at C is larger (120 vs 30).
    ///
    /// C is certified by B.  We compare B's current path to the one
    /// via C.
    ///
    ///   B' forward pointer:        length: 1, amount: 30
    ///   B-C + C's forward pointer: length: 3, amount: 120
    ///
    /// We prefer the existing forward pointer because the path is
    /// shorter *even though the amount of trust is smaller*.  If we
    /// had taken the longer path, then any forward pointers pointing
    /// to B might become invalid.  This is, in fact, the case here:
    /// A-B has a trust depth of 2.  But to use B-C-D-E, A-B would
    /// need a trust depth of at least 3!
    ///
    /// Thus, because we never replace an existing forward pointer
    /// with a forward pointer with a longer path, all forward
    /// pointers remain---by construction---valid.
    ///
    /// # Arguments
    ///
    /// If `self_signed` is true, then the target User ID must be self
    /// signed and the target must be a trusted introducer.  That is,
    /// if 0xB has two self-signed User IDs: `bob@example.org` and
    /// `bob@other.org`, and Alice certifies the first one, then only
    /// the first one would be considered authenticated.  But if Alice
    /// consider Bob via a certification on `bob@example.org` to be a
    /// trusted introducer, then he can certify User IDs on his own
    /// certificate and Alice considers both of his self-signed User
    /// IDs to be authenticated.
    ///
    /// If `self_signed` is false, then self-signed User IDs are not
    /// considered at all.
    ///
    /// `cf` is a callback which returns the trust depth, and trust
    /// amount to use for the certification and whether any regular
    /// expressions should be respected.  To simply use the values in
    /// the certification return None using the callback: `|_| None`.
    // FIXME: public for tests, should be private
    fun backwardPropagate(targetFpr: Fingerprint,
                          targetUserid: String,
                          selfSigned: Boolean,
                          cf: CertificationFilter)
            : HashMap<Fingerprint, Pair<Path, Int>> {

        logger.debug("Query.backward_propagate")

        logger.debug("Roots (${roots.size()}):\n{}",
                this.roots.roots().withIndex().joinToString("\n") { (i, r) ->
                    val fpr = r.fingerprint
                    network.nodes[fpr]?.let { "  {$i}. {$it}" } ?: "  {$i}. {$fpr} (not found)"
                })

        logger.debug("target: {}, {}", targetFpr, targetUserid)
        logger.debug("self signed: {}", selfSigned)

        // If the node is not in the network, we're done.
        val target = network.nodes[targetFpr] ?: return hashMapOf()

        // Make sure the target is valid (not expired and not revoked
        // at the reference time).
        if ((target.expirationTime != null) &&
                (target.expirationTime <= network.referenceTime.timestamp)) {
            logger.debug("{}: Target certificate is expired at reference time.", targetFpr)
            return hashMapOf();
        }

        if (target.revocationState.isEffective(network.referenceTime)) {
            logger.debug("{}: Target certificate is revoked at reference time.", targetFpr)
            return hashMapOf();
        }

        // Recall: the target doesn't need to have self-signed the
        // User ID to authenticate the User ID.  But if the target has
        // revoked it, then it can't be authenticated.
        val targetUa: RevocationState? = target.userIds[targetUserid]
        targetUa?.let {
            if (it.isEffective(network.referenceTime)) {
                logger.debug("{}: Target user id is revoked at reference time.", targetFpr)
                return hashMapOf();
            }
        }

        // Dijkstra.
        val distance: HashMap<Fingerprint, ForwardPointer> = hashMapOf();
        val queue: PairPriorityQueue<Fingerprint, Cost> = PairPriorityQueue();

        fun fpCost(fp0: ForwardPointer): Cost {
            var fp = fp0

            var amount = 120
            var depth: Int = if (selfSigned) 1 else 0

            while (fp.next != null) {
                val c: Edge = fp.next!! // FIXME

                val a = c.trustAmount
                val d = c.trustDepth

                val value = FilterValues(d, a, null)

                val r = cf.cost(c, value, true);
                assert(r) { "cost function returned different result, but must be constant!" };

                amount = min(value.amount, amount)
                depth += 1;
                fp = distance[c.target.fingerprint]!!;
            }

            return Cost(depth, amount)
        }

        if (selfSigned) {
            // If the target is a trusted introducer and has self-signed
            // the User ID, then also consider that path.
            if (targetUa != null) { // FIXME: why can't this be null?!
                logger.debug("Target User ID is self signed.")

                val cost = Cost(1, 120);
                queue.insert(targetFpr, cost);
                distance[targetFpr] = ForwardPointer(null);
            } else {
                logger.debug("Target User ID is not self-signed, but that is required.")
                return hashMapOf();
            }
        } else {
            val cost = Cost(0, 120)
            queue.insert(targetFpr, cost)
            distance[targetFpr] = ForwardPointer(null)
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

            val signee = network.nodes[signeeFpr]!! // already looked up

            // Get the signee's current forward pointer.
            //
            // We need to clone this, because we want to manipulate
            // 'distance' and we can't do that if there is a reference
            // to something in it.
            val signeeFp: ForwardPointer = distance[signeeFpr]!!
            val signeeFpCost = fpCost(signeeFp);

            logger.debug("{}'s forward pointer: {}", signeeFpr, signeeFp.next?.target)

            // Get signeeFp

            // Not limiting by required_depth, because 'network' doesn't expose an interface for this
            val edges: List<EdgeSet> =
                    network.reverseEdgeSet[signeeFpr].orEmpty() // "certifications_of"

            if (edges.isEmpty()) {
                // Nothing certified it.  The path is a dead end.
                logger.debug("{} was not certified, dead end", signeeFpr)
                continue;
            }

            logger.debug("Visiting {} ({}), certified {} times",
                    signee.fingerprint,
                    signee.toString(),
                    edges.size)

            for (certification in edges
                    .map { cs ->
                        cs.certifications
                                .map { it.value }.flatten()
                    }.flatten()) {

                val issuerFpr = certification.issuer.fingerprint

                val fv = FilterValues(certification.trustDepth,
                        certification.trustAmount,
                        certification.regexes)

                if (!cf.cost(certification, fv,
                                false)) {
                    logger.debug("  Cost function says to skip certification by {}", certification.issuer)
                    continue;
                }

                logger.debug("  Considering certification by: {}, depth: {} (of {}), amount: {} (of {}), regexes: {}",
                        certification.issuer,
                        fv.depth,
                        certification.trustDepth,
                        fv.amount,
                        certification.trustAmount,
                        fv.regexps)


                if (fv.amount == 0) {
                    logger.debug("    Edge amount is 0, skipping")
                    continue;
                }

                if (!selfSigned
                        && signeeFpr == targetFpr
                        && certification.userId != targetUserid) {
                    assert(signeeFp.next == null)

                    logger.debug("    Edge certifies target, but for the wrong user id (want: {}, got: {})",
                            targetUserid, certification.userId)

                    continue;
                }

                if (fv.depth < Depth.auto(signeeFpCost.depth)) {
                    logger.debug("    Edge does not have enough depth ({}, needed: {}), skipping", fv.depth, signeeFpCost.depth)
                    continue;
                }

                val re = fv.regexps
                if ((re != null) && !re.matches(targetUserid)) {
                    logger.debug("  Edge's re does not match target User ID, skipping.")
                    continue;
                }

                val proposedFp: ForwardPointer = ForwardPointer(certification)

                val proposedFpCost = Cost(signeeFpCost.depth + 1,
                        min(fv.amount, signeeFpCost.amount))

                logger.debug("  Forward pointer for {}:", certification.issuer)

                val pn = proposedFp.next // cache value for debug output
                logger.debug("    Proposed: {}, amount: {}, depth: {}",
                        pn?.target ?: "target", proposedFpCost.amount, proposedFpCost.depth)

                // distance.entry takes a mutable ref, so we can't
                // compute the current fp's cost in the next block.
                val currentFpCost: Cost? = distance[issuerFpr]?.let { fpCost(it) }

                when (val current_fp = distance[issuerFpr]) {
                    null -> {
                        // We haven't seen this node before.

                        logger.debug("    Current: None")
                        logger.debug("  Setting {}'s forward pointer to {}", certification.issuer, signee)
                        logger.debug("  Queuing {}", certification.issuer)

                        queue.insert(issuerFpr, proposedFpCost);
                        distance[issuerFpr] = proposedFp
                    }

                    else -> {
                        // We've visited this node in the past.  Now
                        // we need to determine whether using
                        // certification and following the proposed
                        // path is better than the current path.

                        val currentFpCost = currentFpCost!!; // shadow the variable

                        val cn = current_fp.next // cache value for debug output
                        logger.debug("    Current: {}, amount: {}, depth: {}",
                                cn?.target ?: "target", currentFpCost.amount, currentFpCost.depth)

                        // We prefer a shorter path (in terms of
                        // edgeSet) as this allows us to reach more of
                        // the graph.
                        //
                        // If the path length is equal, we prefer the
                        // larger amount of trust.

                        if (proposedFpCost.depth < currentFpCost.depth) {
                            if (proposedFpCost.amount < currentFpCost.amount) {
                                // We have two local optima: one has a shorter path, the other a
                                // higher trust amount.  We prefer the shorter path.

                                logger.debug("    Preferring proposed: current has a shorter path ({} < {}), but worse amount of trust ({} < {})",
                                        proposedFpCost.depth, currentFpCost.depth,
                                        proposedFpCost.amount, currentFpCost.amount)

                                distance[issuerFpr] = proposedFp
                            } else {
                                // Proposed fp is strictly better.

                                logger.debug("    Preferring proposed: current has a shorter path ({} < {}), and a better amount of trust ({} < {})",
                                        proposedFpCost.depth, currentFpCost.depth,
                                        proposedFpCost.amount, currentFpCost.amount)

                                distance[issuerFpr] = proposedFp
                            }
                        } else if (proposedFpCost.depth == currentFpCost.depth
                                && proposedFpCost.amount > currentFpCost.amount) {
                            // Strictly better.

                            logger.debug("    Preferring proposed fp: same path length ({}), better amount ({} > {})",
                                    proposedFpCost.depth,
                                    proposedFpCost.amount, currentFpCost.amount)

                            distance[issuerFpr] = proposedFp
                        } else if (proposedFpCost.depth > currentFpCost.depth
                                && proposedFpCost.amount > currentFpCost.amount) {
                            // There's another possible path through here.
                            logger.debug("    Preferring current fp: proposed has more trust ({} > {}), but a longer path ({} > {})",
                                    proposedFpCost.amount, currentFpCost.amount,
                                    proposedFpCost.depth, currentFpCost.depth)
                        } else {
                            logger.debug("    Preferring current fp: it is strictly better (depth: {}, {}; amount: {}, {})",
                                    proposedFpCost.depth, currentFpCost.depth,
                                    proposedFpCost.amount, currentFpCost.amount)
                        }
                    }
                }
            }
        }

        // Follow the forward pointers and reconstruct the paths.
        val authRpaths: HashMap<Fingerprint, Pair<Path, Int>> = hashMapOf();

        for ((issuerFpr, fp) in distance.entries) {
            var fp = fp // Shadow for write access

            // If roots were specified, then only return the optimal
            // paths from the roots.
            if (roots.size() > 0 && !roots.isRoot(issuerFpr)) {
                continue;
            }

            val c = fp.next
            val issuer =
                    if (c != null) {
                        c.issuer
                    } else {

                        // The target.
                        if (!selfSigned) {
                            continue;
                        }

                        // Apply any policy to the self certification.
                        //
                        // XXX: Self-signatures should be first class and not
                        // synthesized like this on the fly.
                        val selfsig = Edge(
                                target, target, targetUserid,

                                // FIXME! Use userid binding signature by default, reference time only as fallback:

                                // target_ua.map(|ua| ua.binding_signature_creation_time())
                                //    .unwrap_or(self.network().reference_time()));

                                network.referenceTime.timestamp
                        )

                        val fv = FilterValues(Depth.auto(0), 120, null)
                        if (cf.cost(selfsig, fv, true)) {
                            logger.debug("Policy on selfsig => amount: {}", fv.amount)

                            if (fv.amount == 0) {
                                continue;
                            }
                        } else {
                            logger.debug("Policy says to ignore selfsig")
                            continue;
                        }

                        val p = Path(target);
                        logger.debug("Authenticated <{}, {}>:\n{}", targetFpr, targetUserid, p)

                        authRpaths[issuerFpr] = Pair(p, fv.amount)

                        continue;
                    };

            logger.debug("Recovering path starting at {}", network.nodes[issuerFpr])

            var amount = 120;

            // nodes[0] is the root; nodes[nodes.len() - 1] is the target.
            val nodes: MutableList<Edge> = mutableListOf();
            while (true) {
                val c = fp.next ?: break

                logger.debug("  {}", fp)

                val fv = FilterValues(c.trustDepth, c.trustAmount, null)

                val r = cf.cost(c, fv, true)

                assert(r) {
                    "cost function returned different result, but must be constant !"
                }
                amount = min(fv.amount, amount);

                nodes.add(c);
                fp = distance[c.target.fingerprint]!! // FIXME !!
            }

            if (selfSigned) {
                val tail = nodes.last()
                if (tail.userId != targetUserid) {
                    val selfsig = Edge(target, target, targetUserid, Date());
                    nodes.add(selfsig);
                }
            }

            logger.debug("  {}", fp)

            logger.debug("\nShortest path from {} to <{} <-> {}>:\n  {}",
                    issuer.fingerprint,
                    targetUserid, targetFpr,
                    nodes.withIndex().joinToString("\n  ") { (i, certification) ->
                        "$i: $certification"
                    })

            assert(nodes.size > 0);

            val p = Path(issuer);
            for (n in nodes.iterator()) {
                p.append(n)
            }
            logger.debug("Authenticated <{}, {}>:\n{}", targetFpr, targetUserid, p)

            authRpaths[issuerFpr] = Pair(p, amount);
        }

        //        if TRACE {
        //            t!("auth_rpaths:");
        //            let mut v: Vec<_> = auth_rpaths.iter().collect();
        //            v.sort_by(|(fpr_a, _), (fpr_b, _)| {
        //            let userid_a = self.network()
        //                    .lookup_synopsis_by_fpr(*fpr_a).expect("already looked up")
        //                    .primary_userid().map(|userid| {
        //                String::from_utf8_lossy(userid.value()).into_owned()
        //            }).unwrap_or("".into());
        //            let userid_b = self.network()
        //                    .lookup_synopsis_by_fpr(*fpr_b).expect("already looked up")
        //                    .primary_userid().map(|userid| {
        //                String::from_utf8_lossy(userid.value()).into_owned()
        //            }).unwrap_or("".into());
        //
        //            userid_a.cmp(&userid_b).
        //            then(fpr_a.cmp(&fpr_b))
        //        });
        //            for (fpr, (path, amount)) in v {
        //            let userid = self.network()
        //                    .lookup_synopsis_by_fpr(fpr).expect("already looked up")
        //                    .primary_userid().map(|userid| {
        //                String::from_utf8_lossy(userid.value()).into_owned()
        //            })
        //            .unwrap_or("<missing User ID>".into());
        //            t!("  <{}, {}>: {}",
        //            fpr, userid,
        //            format!("{} trust amount (max: {}), {} edgeSet",
        //            amount, path.amount(),
        //            path.len() - 1));
        //        }
        //        }

        return authRpaths
    }
}
