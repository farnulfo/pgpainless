// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: LGPL-2.0-or-later

package org.pgpainless.wot.query

import org.pgpainless.wot.network.*
import org.sequoia_pgp.wot.vectors.*
import java.time.Instant
import java.util.Date
import kotlin.RuntimeException
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Tests for the authenticate function of the Web of Trust algorithm, as outlined in
 * https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/spec/sequoia-wot.md
 *
 * These tests are ported from https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/src/lib.rs
 * by Neal H. Walfield <neal@pep.foundation>, licensed under LGPL-2.0-or-later.
 */
class AuthenticateTest {

    // Authenticates the target.
    private fun sp(q: Query,
                   targetFpr: Fingerprint,
                   targetUserid: String,
                   expected: List<Pair<Int, List<Fingerprint>>>,
                   minTrustAmount: Int?) {

        println("Authenticating: $targetFpr, $targetUserid");

        val got = q.authenticate(targetFpr, targetUserid, (minTrustAmount ?: 120))

        when (Pair(got.paths.isNotEmpty(), expected.isNotEmpty())) {
            Pair(false, false) -> {
                println("Can't authenticate == can't authenticate (good)");
            }

            Pair(false, true) -> {
                throw RuntimeException("Couldn't authenticate. Expected paths: $expected")
            }

            Pair(true, false) -> {
                throw RuntimeException("Unexpectedly authenticated binding. Got: $got")
            }

            Pair(true, true) -> {
                println("Got paths: ${got.items}")
                println("Expected: $expected")

                assertEquals(expected.size, got.paths.size, "Expected $expected paths, got ${got.paths} [${got.amount}]")
                got.items.map { (path, amount) ->
                    Pair(amount, path.certificates.map { it.fingerprint }.toList())
                }.zip(expected).withIndex()
                        .forEach { (i, b) ->
                            val g = b.first
                            var e = b.second

                            // Adjust test expectations: sequoia-wot returns 1-step paths for self-signed roots.
                            // We return a 2-step path.
                            if (e.second.size == 1) {
                                val list = e.second.toMutableList()
                                list.add(list[0])
                                e = Pair(e.first, list.toList())
                            }

                            assertEquals(e, g, "got vs. expected path (#$i)")
                            assertEquals(e.first, g.first, "got vs. expected trust amount (#$i)")
                        }

                assertEquals(expected.sumOf { it.first }, got.amount)
            }
        }

        // NOTE: we're not checking the validity of the path on the OpenPGP layer
    }

    private fun printNetwork(n: Network) {
        println("Network contains " + n.nodes.size + " nodes with " + n.numberOfEdges + " edges built from "
                + n.numberOfSignatures + " signatures.")
        println(n)
    }

    @Test
    fun simple() {
        val t = SimpleVectors()
        val n = t.getNetworkAt()

        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

        sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)
        sp(q1, t.bobFpr, t.bobUid, listOf(Pair(100, listOf(t.aliceFpr, t.bobFpr))), null)
        sp(q1, t.carolFpr, t.carolUid, listOf(Pair(100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
        sp(q1, t.daveFpr, t.daveUid, listOf(Pair(100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr))), null)
        sp(q1, t.ellenFpr, t.ellenUid, listOf(), null)
        sp(q1, t.frankFpr, t.frankUid, listOf(), null)
        sp(q1, t.carolFpr, t.bobUid, listOf(), null) // No one authenticated Bob's User ID on Carol's key.

        val q2 = Query(n, Roots(listOf(Root(t.bobFpr))), false)

        sp(q2, t.aliceFpr, t.aliceUid, listOf(), null)
        sp(q2, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.bobFpr))), null)
        sp(q2, t.carolFpr, t.carolUid, listOf(Pair(100, listOf(t.bobFpr, t.carolFpr))), null)
        sp(q2, t.daveFpr, t.daveUid, listOf(Pair(100, listOf(t.bobFpr, t.carolFpr, t.daveFpr))), null)
        sp(q2, t.ellenFpr, t.ellenUid, listOf(), null)
        sp(q2, t.frankFpr, t.frankUid, listOf(), null)
        sp(q2, t.carolFpr, t.bobUid, listOf(), null) // No one authenticated Bob's User ID on Carol's key.
    }

    @Test
    fun cycle() {
        val t = CycleVectors()
        val n = t.getNetworkAt()

        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

        sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)
        sp(q1, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.aliceFpr, t.bobFpr))), null)
        sp(q1, t.carolFpr, t.carolUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
        sp(q1, t.daveFpr, t.daveUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr))), null)
        sp(q1, t.edFpr, t.edUid, listOf(Pair(30, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr))), null)
        sp(q1, t.frankFpr, t.frankUid, listOf(), null)

        val q2 = Query(n, Roots(listOf(Root(t.aliceFpr), Root(t.daveFpr))), false)

        sp(q2, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)

        // The following paths are identical and the sorting depends on the fingerprint.
        // Thus, regenerating the keys could create a failure.
        sp(q2, t.bobFpr, t.bobUid,
                listOf(Pair(120, listOf(t.aliceFpr, t.bobFpr)),
                        Pair(120, listOf(t.daveFpr, t.bobFpr))),
                300)

        sp(q2, t.carolFpr, t.carolUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
        sp(q2, t.edFpr, t.edUid, listOf(Pair(30, listOf(t.daveFpr, t.edFpr))), null)
        sp(q2, t.frankFpr, t.frankUid, listOf(Pair(30, listOf(t.daveFpr, t.edFpr, t.frankFpr))), null)
    }

    @Test
    fun cliques() {
        val t1 = CliquesVectors()
        val n1 = t1.getNetworkAt()
        printNetwork(n1)

        val q1 = Query(n1, Roots(listOf(Root(t1.rootFpr))), false)

        // root -> a-0 -> a-1 -> b-0 -> ... -> f-0 -> target
        sp(q1, t1.targetFpr, t1.targetUid,
                listOf(Pair(120, listOf(t1.rootFpr, t1.a0Fpr, t1.a1Fpr, t1.b0Fpr, t1.b1Fpr, t1.c0Fpr, t1.c1Fpr, t1.d0Fpr, t1.d1Fpr, t1.e0Fpr, t1.f0Fpr, t1.targetFpr))),
                null)

        val q2 = Query(n1, Roots(listOf(Root(t1.a1Fpr))), false)

        sp(q2, t1.targetFpr, t1.targetUid,
                listOf(Pair(120, listOf(t1.a1Fpr, t1.b0Fpr, t1.b1Fpr, t1.c0Fpr, t1.c1Fpr, t1.d0Fpr, t1.d1Fpr, t1.e0Fpr, t1.f0Fpr, t1.targetFpr))),
                null)

        val t2 = CliquesLocalOptimaVectors()
        val n2 = t2.getNetworkAt()
        printNetwork(n2)

        val q3 = Query(n2, Roots(listOf(Root(t2.rootFpr))), false)

        // root -> b-0 -> ... -> f-0 -> target
        sp(q3, t2.targetFpr, t2.targetUid,
                listOf(Pair(30, listOf(t2.rootFpr, t2.b0Fpr, t2.b1Fpr, t2.c0Fpr, t2.c1Fpr, t2.d0Fpr, t2.d1Fpr, t2.e0Fpr, t2.f0Fpr, t2.targetFpr)),
                        Pair(30, listOf(t2.rootFpr, t2.a1Fpr, t2.b0Fpr, t2.b1Fpr, t2.c0Fpr, t2.c1Fpr, t2.d0Fpr, t2.d1Fpr, t2.e0Fpr, t2.f0Fpr, t2.targetFpr)),
                        Pair(60, listOf(t2.rootFpr, t2.a0Fpr, t2.a1Fpr, t2.b0Fpr, t2.b1Fpr, t2.c0Fpr, t2.c1Fpr, t2.d0Fpr, t2.d1Fpr, t2.e0Fpr, t2.f0Fpr, t2.targetFpr))),
                null)

        val q4 = Query(n2, Roots(listOf(Root(t2.a1Fpr))), false)

        sp(q4, t2.targetFpr, t2.targetUid,
                listOf(Pair(120, listOf(t2.a1Fpr, t2.b0Fpr, t2.b1Fpr, t2.c0Fpr, t2.c1Fpr, t2.d0Fpr, t2.d1Fpr, t2.e0Fpr, t2.f0Fpr, t2.targetFpr))),
                null)


        val t3 = CliquesLocalOptima2Vectors()
        val n3 = t3.getNetworkAt()
        printNetwork(n3)

        val q5 = Query(n3, Roots(listOf(Root(t3.rootFpr))), false)

        // root -> b-0 -> ... -> f-0 -> target
        sp(q5, t3.targetFpr, t3.targetUid,
                listOf(Pair(30, listOf(t3.rootFpr, t3.b0Fpr, t3.b1Fpr, t3.c1Fpr, t3.d0Fpr, t3.d1Fpr, t3.e0Fpr, t3.f0Fpr, t3.targetFpr)),
                        Pair(30, listOf(t3.rootFpr, t3.a1Fpr, t3.b0Fpr, t3.b1Fpr, t3.c0Fpr, t3.c1Fpr, t3.d0Fpr, t3.d1Fpr, t3.e0Fpr, t3.f0Fpr, t3.targetFpr)),
                        Pair(60, listOf(t3.rootFpr, t3.a0Fpr, t3.a1Fpr, t3.b0Fpr, t3.b1Fpr, t3.c0Fpr, t3.c1Fpr, t3.d0Fpr, t3.d1Fpr, t3.e0Fpr, t3.f0Fpr, t3.targetFpr))),
                null)

        val q6 = Query(n3, Roots(listOf(Root(t3.a1Fpr))), false)

        sp(q6, t3.targetFpr, t3.targetUid,
                listOf(Pair(30, listOf(t3.a1Fpr, t3.b0Fpr, t3.b1Fpr, t3.c1Fpr, t3.d0Fpr, t3.d1Fpr, t3.e0Fpr, t3.f0Fpr, t3.targetFpr)),
                        Pair(90, listOf(t3.a1Fpr, t3.b0Fpr, t3.b1Fpr, t3.c0Fpr, t3.c1Fpr, t3.d0Fpr, t3.d1Fpr, t3.e0Fpr, t3.f0Fpr, t3.targetFpr))),
                null)
    }

    @Test
    fun roundabout() {
        val t = RoundaboutVectors()
        val n = t.getNetworkAt()
        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

        sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)

        sp(q1, t.bobFpr, t.bobUid,
                listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr)),
                        Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr, t.frankFpr, t.bobFpr))
                ),
                null)

        sp(q1, t.carolFpr, t.carolUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr))), null)

        sp(q1, t.daveFpr, t.daveUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr))), null)

        sp(q1, t.elmarFpr, t.elmarUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr))), null)

        sp(q1, t.frankFpr, t.frankUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr, t.frankFpr))), null)

        sp(q1, t.georgeFpr, t.georgeUid,
                listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr)),
                        Pair(60, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr,
                                t.frankFpr, t.bobFpr, t.georgeFpr))),
                null)

        sp(q1, t.henryFpr, t.henryUid,
                listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr, t.henryFpr)),
                        Pair(60, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr,
                                t.frankFpr, t.bobFpr, t.georgeFpr, t.henryFpr))),
                null)

        sp(q1, t.isaacFpr, t.isaacUid,
                listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr, t.henryFpr, t.isaacFpr))),
                null)

        sp(q1, t.jennyFpr, t.jennyUid, listOf(), null)


        val q2 = Query(n, Roots(listOf(Root(t.jennyFpr))), false)

        sp(q2, t.aliceFpr, t.aliceUid, listOf(), null)

        sp(q2, t.bobFpr, t.bobUid, listOf(Pair(100, listOf(t.jennyFpr, t.elmarFpr, t.frankFpr, t.bobFpr))), null)

        sp(q2, t.carolFpr, t.carolUid, listOf(), null)

        sp(q2, t.daveFpr, t.daveUid, listOf(), null)

        sp(q2, t.elmarFpr, t.elmarUid, listOf(Pair(100, listOf(t.jennyFpr, t.elmarFpr))), null)

        sp(q2, t.frankFpr, t.frankUid, listOf(Pair(100, listOf(t.jennyFpr, t.elmarFpr, t.frankFpr))), null)

        sp(q2, t.georgeFpr, t.georgeUid,
                listOf(Pair(100, listOf(t.jennyFpr, t.georgeFpr)),
                        Pair(100, listOf(t.jennyFpr, t.elmarFpr, t.frankFpr, t.bobFpr, t.georgeFpr))
                ), null)

        sp(q2, t.henryFpr, t.henryUid,
                listOf(Pair(100, listOf(t.jennyFpr, t.georgeFpr, t.henryFpr)),
                        Pair(20, listOf(t.jennyFpr, t.elmarFpr, t.frankFpr, t.bobFpr, t.georgeFpr, t.henryFpr))
                ), null)

        sp(q2, t.isaacFpr, t.isaacUid, listOf(), null)

        sp(q2, t.jennyFpr, t.jennyUid, listOf(Pair(120, listOf(t.jennyFpr))), null)


        val q3 = Query(n, Roots(listOf(Root(t.aliceFpr), Root(t.jennyFpr))), false)

        sp(q3, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)

        // In the first iteration of backwards_propagate, we find two paths:
        //
        //   A -> B (60)
        //   J -> E -> F -> B (100)
        //
        // It doesn't find:
        //
        //   A -> C -> D -> E -> F -> B (120)
        //
        // Query::authenticate chooses the path rooted at J,
        // because it has more trust.  Then we call
        // backwards_propagate again and find:
        //
        //   A -> B (60)
        //
        // Finally, we call backwards a third time and find:
        //
        //   A -> C -> D -> E -> F -> B (120 -> 20)
        sp(q3, t.bobFpr, t.bobUid,
                listOf(Pair(100, listOf(t.jennyFpr, t.elmarFpr, t.frankFpr, t.bobFpr)),
                        Pair(60, listOf(t.aliceFpr, t.bobFpr)),
                        Pair(20, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr, t.frankFpr, t.bobFpr))
                ), 240)

        sp(q3, t.carolFpr, t.carolUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr))), null)

        sp(q3, t.daveFpr, t.daveUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr))), null)

        sp(q3, t.elmarFpr, t.elmarUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr))), null)

        sp(q3, t.frankFpr, t.frankUid, listOf(Pair(120, listOf(t.aliceFpr, t.carolFpr, t.daveFpr, t.elmarFpr, t.frankFpr))), 240);

        sp(q3, t.georgeFpr, t.georgeUid,
                listOf(
                        Pair(100, listOf(t.jennyFpr, t.georgeFpr)),
                        Pair(100, listOf(t.jennyFpr, t.elmarFpr, t.frankFpr, t.bobFpr, t.georgeFpr)),
                        Pair(20, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr)),
                ), 240)

        sp(q3, t.henryFpr, t.henryUid,
                listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr, t.henryFpr)),
                        Pair(60, listOf(t.jennyFpr, t.georgeFpr, t.henryFpr))
                ), null)

        sp(q3, t.isaacFpr, t.isaacUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr, t.henryFpr, t.isaacFpr))), null)

        sp(q3, t.jennyFpr, t.jennyUid, listOf(Pair(120, listOf(t.jennyFpr))), null)
    }

    @Test
    fun localOptima() {
        val t = LocalOptimaVectors()
        val n = t.getNetworkAt()
        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

        sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)

        sp(q1, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.aliceFpr, t.bobFpr))), null)

        sp(q1, t.carolFpr, t.carolUid, listOf(Pair(100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)

        sp(q1, t.daveFpr, t.daveUid, listOf(Pair(50, listOf(t.aliceFpr, t.bobFpr, t.daveFpr))), null)

        sp(q1, t.ellenFpr, t.ellenUid,
                listOf(
                        Pair(100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.ellenFpr)),
                        Pair(20, listOf(t.aliceFpr, t.bobFpr, t.daveFpr, t.ellenFpr)),
                ), null)

        sp(q1, t.francisFpr, t.francisUid,
                listOf(
                        Pair(75, listOf(t.aliceFpr, t.bobFpr, t.francisFpr)),
                        Pair(45, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.ellenFpr, t.francisFpr)),
                ), null)

        sp(q1, t.georginaFpr, t.georginaUid, listOf(Pair(30, listOf(t.aliceFpr, t.bobFpr, t.daveFpr, t.ellenFpr, t.georginaFpr))), null)

        sp(q1, t.henryFpr, t.henryUid,
                listOf(
                        Pair(100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.ellenFpr, t.henryFpr)),
                        Pair(20, listOf(t.aliceFpr, t.bobFpr, t.daveFpr, t.ellenFpr, t.henryFpr)),
                ), null)


        val q2 = Query(n, Roots(listOf(Root(t.bobFpr))), false)

        sp(q2, t.aliceFpr, t.aliceUid, listOf(), null)

        sp(q2, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.bobFpr))), null)

        sp(q2, t.carolFpr, t.carolUid, listOf(Pair(100, listOf(t.bobFpr, t.carolFpr))), null)

        sp(q2, t.daveFpr, t.daveUid, listOf(Pair(50, listOf(t.bobFpr, t.daveFpr))), null)

        sp(q2, t.ellenFpr, t.ellenUid,
                listOf(
                        Pair(100, listOf(t.bobFpr, t.carolFpr, t.ellenFpr)),
                        Pair(50, listOf(t.bobFpr, t.daveFpr, t.ellenFpr)),
                ), null)

        sp(q2, t.francisFpr, t.francisUid,
                listOf(
                        Pair(75, listOf(t.bobFpr, t.francisFpr)),
                        Pair(100, listOf(t.bobFpr, t.carolFpr, t.ellenFpr, t.francisFpr)),
                        Pair(20, listOf(t.bobFpr, t.daveFpr, t.ellenFpr, t.francisFpr)),
                ), 240)
    }

    @Test
    fun multipleUserids3() {
        val t = MultipleUserIds3Vectors()
        val n = t.getNetworkAt()
        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

        sp(q1, t.frankFpr, t.frankUid,
                listOf(
                        Pair(20, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.frankFpr)),
                        Pair(10, listOf(t.aliceFpr, t.bobFpr, t.daveFpr, t.edFpr, t.frankFpr)),
                ), null)
    }

    @Test
    fun certificationLiveness() {
        val t = CertificationLivenessVectors()

        for ((i, time) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            val q = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            val amount = when (i + 1) {
                1 -> 60
                2 -> 120
                3 -> 60
                else -> throw RuntimeException("")
            }

            sp(q, t.carolFpr, t.carolUid, listOf(Pair(amount, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
        }
    }

    @Test
    fun certRevokedSoft() {
        val t = CertRevokedSoftVectors()

        for ((i, time) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            // At t1, soft revocations are in the future, so certifications are still valid.
            //
            // At t2, B is soft-revoked, so existing certifications are still valid, but we can no longer
            // authenticate B.
            //
            // At t3, A re-certifies B and B re-certifies D. These certifications should be ignored as they are made
            // after B was revoked.

            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            // Consider just the code path where B is the issuer.
            //
            // Covers scenarios #1 at t1, #3 at t2 and t3
            val q1 = Query(n, Roots(listOf(Root(t.bobFpr))), false)
            sp(q1, t.daveFpr, t.daveUid, listOf(Pair(60, listOf(t.bobFpr, t.daveFpr))), null)


            val q2 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            // Consider just the code path where B is the target.
            //
            // Covers scenarios #2 at t1, #4 at t2 and t3.
            if (i + 1 == 1) {
                sp(q2, t.bobFpr, t.bobUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr))), null)
            } else {
                sp(q2, t.bobFpr, t.bobUid, listOf(), null)
            }

            // Consider the code path where B is both an issuer and a target.
            //
            // Covers scenarios #1 & #2 at t1, #3 & #4 at t2 and t3.
            sp(q2, t.daveFpr, t.daveUid,
                    listOf(
                            Pair(60, listOf(t.aliceFpr, t.bobFpr, t.daveFpr)),
                            Pair(30, listOf(t.aliceFpr, t.carolFpr, t.daveFpr)),
                    ), null)
        }

    }

    @Test
    fun certRevokedHard() {
        val t = CertRevokedHardVectors()

        // At t1, B is hard revoked in the future so all certifications are invalid.
        //
        // At t2, B is hard revoked so all certifications are invalid.
        //
        // At t3, A re-certifies B and B re-certifies D. These certifications should also be ignored.
        for ((i, time) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            // Consider just the code path where B is the issuer.
            //
            // Covers scenarios #5 at t1, #7 at t2 and t3
            val q1 = Query(n, Roots(listOf(Root(t.bobFpr))), false)
            sp(q1, t.daveFpr, t.daveUid, listOf(), null)

            val q2 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            // Consider just the code path where B is the target.
            //
            // Covers scenarios #6 at t1, #8 at t2 and t3.
            sp(q2, t.bobFpr, t.bobUid, listOf(), null)

            // Consider the code path where B is both an issuer and a target.
            //
            // Covers scenarios #5 & #6 at t1, #7 & #8 at t2 and t3.
            sp(q2, t.daveFpr, t.daveUid, listOf(Pair(30, listOf(t.aliceFpr, t.carolFpr, t.daveFpr))), null)
        }
    }

    @Test
    fun certExpired() {
        val t = CertExpiredVectors()

        for ((i, time) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            // Bob as target.
            // (Once Bob has expired, it can be used as a trusted introducer for prior certifications, but
            // bindings cannot be authenticated.)
            if (i + 1 == 1) {
                sp(q1, t.bobFpr, t.bobUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr))), null)
            } else {
                sp(q1, t.bobFpr, t.bobUid, listOf(), null)
            }

            // Bob in the middle.
            sp(q1, t.carolFpr, t.carolUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)

            // Bob as root.
            val q2 = Query(n, Roots(listOf(Root(t.bobFpr))), false)
            sp(q2, t.carolFpr, t.carolUid, listOf(Pair(60, listOf(t.bobFpr, t.carolFpr))), null)

            // Bob's self signature.
            if (i + 1 == 1) {
                sp(q2, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.bobFpr))), null)
            } else {
                sp(q2, t.bobFpr, t.bobUid, listOf(), null)
            }
        }
    }

    @Test
    fun userIdRevoked() {
        val t = UserIdRevokedVectors()

        // At t2, B is soft-revoked so all future certifications are invalid.
        for ((i, time) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            // Revoked User ID on the root.
            val q1 = Query(n, Roots(listOf(Root(t.bobFpr))), false)

            if (i + 1 == 1) {
                sp(q1, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.bobFpr))), null)
            } else {
                sp(q1, t.bobFpr, t.bobUid, listOf(), null)
            }

            val q2 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            if (i + 1 == 1) {
                sp(q2, t.bobFpr, t.bobUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr))), null)
            } else {
                // Can't authenticate binding with a revoked User ID.
                sp(q2, t.bobFpr, t.bobUid, listOf(), null)
            }

            // Can use a delegation even if the certification that it is a part of has had its User ID revoked.
            if (i + 1 < 3) {
                sp(q2, t.carolFpr, t.carolUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
            } else {
                sp(q2, t.carolFpr, t.carolUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
            }
        }
    }

    @Test
    fun certificationsRevoked() {
        val t = CertificationRevokedVectors()

        for ((i, time) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            // Revoked User ID on the root.
            val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)

            when (i + 1) {
                1 -> {
                    sp(q1, t.bobFpr, t.bobUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr))), null)
                    sp(q1, t.carolFpr, t.carolUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
                }

                2 -> {
                    sp(q1, t.bobFpr, t.bobUid, listOf(), null)
                    sp(q1, t.carolFpr, t.carolUid, listOf(), null)
                }

                3 -> {
                    sp(q1, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.aliceFpr, t.bobFpr))), null)
                    sp(q1, t.carolFpr, t.carolUid, listOf(Pair(120, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
                }

                else -> throw RuntimeException() // unreachable
            }

            // Alice, not Bob, revokes Bob's user id. So when Bob is the root, the self-signature should still be good.
            val q2 = Query(n, Roots(listOf(Root(t.bobFpr))), false)
            sp(q2, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.bobFpr))), null)
        }
    }

    @Test
    fun infinityAndBeyond() {
        val t = InfinityAndBeyondVectors()
        val n = t.getNetworkAt()
        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.u1Fpr))), false)

        // This should always work.
        sp(q1, t.u254Fpr, t.u254Uid, listOf(Pair(120, t.fprs.subList(0, 254))), null)

        // This tests that depth=255 really means infinity.
        sp(q1, t.u260Fpr, t.u260Uid, listOf(Pair(120, t.fprs)), null)
    }

    @Test
    fun zeroTrust() {
        val t = ZeroTrustVectors()

        // At t2, B is certified with a trust amount of 0. This should eliminate the path.
        for ((i, time) in listOf<Long>(1580598000, 1583103600).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            if (i + 1 == 1) {
                sp(q1, t.carolFpr, t.carolUid, listOf(Pair(60, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
            } else {
                sp(q1, t.carolFpr, t.carolUid, listOf(), null)
            }

            // Start with bob and make sure that a certification by a root with a 0 trust amount is also respected.
            val q2 = Query(n, Roots(listOf(Root(t.bobFpr))), false)

            if (i + 1 == 1) {
                sp(q2, t.carolFpr, t.carolUid, listOf(Pair(60, listOf(t.bobFpr, t.carolFpr))), null)
            } else {
                sp(q2, t.carolFpr, t.carolUid, listOf(), null)
            }
        }
    }

    @Test
    fun partiallyTrustedRoots() {
        val t = SimpleVectors()
        val n = t.getNetworkAt()
        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr, 90))), false)
        sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(90, listOf(t.aliceFpr))), null)
        sp(q1, t.bobFpr, t.bobUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr))), null)
        sp(q1, t.carolFpr, t.carolUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
        sp(q1, t.daveFpr, t.daveUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr))), null)
        sp(q1, t.ellenFpr, t.ellenUid, listOf(), null)
        sp(q1, t.frankFpr, t.frankUid, listOf(), null)

        // No one authenticated Bob's User ID on Carol's key.
        sp(q1, t.carolFpr, t.bobUid, listOf(), null)

        // Multiple partially trusted roots. Check that together they can fully certify a self-signature.
        val q2 = Query(n, Roots(listOf(Root(t.aliceFpr, 90), Root(t.bobFpr, 90))), false)

        sp(q2, t.aliceFpr, t.aliceUid, listOf(Pair(90, listOf(t.aliceFpr))), null)

        // NOTE: original expectation from sequoia-wot:
        //        sp(q2, t.bobFpr, t.bobUid,
        //                listOf(Pair(90, listOf(t.bobFpr)),
        //                        Pair(90, listOf(t.aliceFpr, t.bobFpr))), null)

        // Our changed expectation: the order has changed because we return self-signed roots including the
        // self-certification edge.
        // This also happens to result in different ordering of the two paths, in this case.
        sp(q2, t.bobFpr, t.bobUid,
                listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr)),
                        Pair(90, listOf(t.bobFpr))
                ), null)
    }

    @Test
    fun selfSigned() {
        val t = SelfSignedVectors()
        val n = t.getNetworkAt()
        printNetwork(n)

        val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)
        sp(q1, t.bobFpr, t.bobUid, listOf(Pair(100, listOf(t.aliceFpr, t.bobFpr))), null)
        sp(q1, t.carolFpr, t.carolUid, listOf(Pair(90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))), null)
        sp(q1, t.carolFpr, t.carolOtherOrgUid, listOf(), null)
        sp(q1, t.daveFpr, t.daveUid, listOf(), null)

        val q2 = Query(n, Roots(listOf(Root(t.bobFpr))), false)
        sp(q2, t.bobFpr, t.bobUid, listOf(Pair(120, listOf(t.bobFpr))), null)
        sp(q2, t.carolFpr, t.carolUid, listOf(Pair(90, listOf(t.bobFpr, t.carolFpr))), null)
        sp(q2, t.carolFpr, t.carolOtherOrgUid, listOf(Pair(90, listOf(t.bobFpr, t.carolFpr, t.carolFpr))), null)
        sp(q2, t.daveFpr, t.daveUid, listOf(Pair(90, listOf(t.bobFpr, t.carolFpr, t.daveFpr))), null)
    }

    @Test
    fun isolatedRoot() {
        val t = IsolatedRootVectors()

        for ((i, time) in listOf<Long>(1577919600, 1580598000).withIndex()) {
            val date = Date(Instant.ofEpochSecond(time).toEpochMilli())
            println("Trying at #$i $date");

            val n = t.getNetworkAt(ReferenceTime.timestamp(date))
            printNetwork(n)

            val q1 = Query(n, Roots(listOf(Root(t.aliceFpr))), false)

            if (i == 0) {
                sp(q1, t.aliceFpr, t.aliceUid, listOf(Pair(120, listOf(t.aliceFpr))), null)
            } else {
                sp(q1, t.aliceFpr, t.aliceUid, listOf(), null)
            }

            sp(q1, t.aliceFpr, t.aliceOtherOrgUid, listOf(Pair(120, listOf(t.aliceFpr))), null)
        }
    }

}