package org.pgpainless.wot.query

import org.pgpainless.wot.network.*

/**
 * A wrapper for `Network` that performs the following functions:
 *
 * - Expose an (experimental) API that simplifies the implementation of the WoT algorithm (in `Query`)
 *   - TODO: polish, and possibly upstream into `Network`
 *
 * - Form residual networks for the Ford-Fulkerson algorithm via `suppressPath()`
 *   - `getEffectiveTrustAmount()` returns effective trust amounts of certifications
 *     (taking the residual network into account)
 */
internal class WotNetwork(private val network: Network, private val certificationNetwork: Boolean) {

    fun nodeByFpr(fpr: Fingerprint): Node? = network.nodes[fpr]

    fun getSelfSig(targetFpr: Fingerprint, targetUserid: String): EdgeComponent? {
        val target = nodeByFpr(targetFpr)

        if (target?.userIds?.get(targetUserid) != null) {
            // Return a synthesized self-binding.
            // XX: This EC should be generated during network generation.
            return EdgeComponent(target, target, targetUserid, network.referenceTime.timestamp,
                    null, true, 120, Depth.limited(0), RegexSet.wildcard())
        } else
            return null
    }

    /**
     * Return list of EdgeComponents that point to `fpr`.
     *
     * Doesn't currently return self-bindings.
     *
     * `targetUserid` is currently only evaluated to check matching with regex scoped delegations.
     * Doesn't currently filter out EdgeComponents that point to `fpr`, but a different User ID
     * (FIXME: filter by target User ID, if fpr == target, and target user id != null, then simplify Query?)
     *
     * In authentication network mode:
     * - only return EdgeComponents whose depth allows authentication of a path that is `curLen` long.
     * - only return EdgeComponents whose regexes match `targetUserid`.
     */
    fun certificationsForSignee(fpr: Fingerprint, targetUserid: String, curLen: Int): List<EdgeComponent> {
        val edges = network.reverseEdges[fpr] ?: return listOf()

        val ec = edges.map { edge ->
            edge.components.map { it.value }.flatten()
        }
                .flatten()
                .filter {
                    if (!certificationNetwork) {
                        // Authentication network mode: honor depth limitation and regexes
                        it.trustDepth >= curLen && it.regexes.matches(targetUserid)
                    } else {
                        // Certification network mode: Keep certifications of any depth, and ignore regex scoping
                        true
                    }
                }

        return ec
    }

    fun isValidTarget(targetFpr: Fingerprint, targetUserid: String): Node? {

        // Node must be in the network.
        val target = nodeByFpr(targetFpr) ?: return null

        // Target may not be expired at the reference time.
        if ((target.expirationTime != null) &&
                (target.expirationTime <= network.referenceTime.timestamp)) {
            return null
        }

        // Target may not be revoked at the reference time.
        if (target.revocationState.isEffective(network.referenceTime)) {
            return null
        }

        // The target doesn't need to have self-signed the User ID to authenticate the User ID.
        // But if the target has revoked it, then it can't be authenticated.
        val targetUa: RevocationState? = target.userIds[targetUserid]
        if (targetUa != null && targetUa.isEffective(network.referenceTime)) {
            return null
        }

        return target
    }


    // Modifiers are processed in order by getEffectiveTrustAmount() [first cap, then suppress]
    private val capCertificate: HashMap<Fingerprint, Int> = HashMap()
    private val suppressPath: HashMap<Pair<Fingerprint, Fingerprint>, Int> = HashMap()

    /**
     * Get effective trust amount for a certification:
     * Cap if the root has limited trust, and take into account additional constraints of the residual network.
     */
    fun getEffectiveTrustAmount(ec: EdgeComponent): Int {
        // Start from trust amount on the certification
        var amount = ec.trustAmount

        // Cap to issuer's `capCertificate`, if set.
        // (Used in case of less than fully trusted roots)
        capCertificate[ec.issuer.fingerprint]?.let {
            if (it < amount) {
                amount = it
            }
        }

        // Suppress by certificate (for Ford-Fulkerson residual network)
        suppressPath[Pair(ec.issuer.fingerprint, ec.target.fingerprint)]?.let {
            if (amount > it) {
                amount -= it
            } else {
                amount = 0
            }
        }

        return amount
    }

    /** Limit a certificate's initial trust amount to `amount` */
    fun capCertificate(fingerprint: Fingerprint, amount: Int) {
        capCertificate[fingerprint] = amount
    }

    /**
     * Add suppression rules for all certifications along the specified path:
     * Each edge is suppressed by `amountToSuppress`.
     */
    fun suppressPath(path: Path, amountToSuppress: Int) {
        if (amountToSuppress == 0) return
        assert(amountToSuppress <= 120)

        for (c in path.certifications) {
            val curAmount = suppressPath[Pair(c.issuer.fingerprint, c.target.fingerprint)] ?: 0
            val newAmount = curAmount + amountToSuppress
            assert(newAmount <= 120)

            suppressPath[Pair(c.issuer.fingerprint, c.target.fingerprint)] = newAmount
        }
    }
}