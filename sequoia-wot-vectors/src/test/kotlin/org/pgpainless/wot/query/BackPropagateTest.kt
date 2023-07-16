// SPDX-FileCopyrightText: 2023 Neal H. Walfield <neal@pep.foundation>, Heiko Schaefer <heiko@schaefer.name>
//
// SPDX-License-Identifier: LGPL-2.0-or-later

package org.pgpainless.wot.query

import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Root
import org.pgpainless.wot.network.Roots
import org.pgpainless.wot.query.Path
import org.sequoia_pgp.wot.vectors.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

internal const val DEPTH_UNCONSTRAINED = 255

/**
 * Tests for the backward propagation function of the Web of Trust algorithm, as outlined in
 * https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/spec/sequoia-wot.md
 *
 * These tests are ported from https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/src/backward_propagation.rs
 * by Neal H. Walfield <neal@pep.foundation>, licensed under LGPL-2.0-or-later.
 */
class BackPropagateTest {

    // Compares a computed path and a trust amount with the expected result.
    private fun checkResult(result: Pair<Path, Int>, residualDepth: Int, amount: Int, expectedPath: List<Fingerprint>) {
        val (gotPath, gotAmount) = result;
        val gotCerts: List<Fingerprint> = gotPath.certificates.map { it.fingerprint }

        assertEquals(expectedPath.size, gotCerts.size)
        assert(gotCerts.zip(expectedPath).none { it.first != it.second }) // FIXME: debug output?

        println("got $gotPath")
        println("expected $expectedPath")

        assertEquals(amount, gotAmount, "Trust amount mismatch")
        assertEquals(residualDepth, gotPath.residualDepth.value(), "Residual depth mismatch")

        // NOTE: The Rust tests also check for validity of the path, but we're separating those concerns here.
        // This package only deals with WoT calculations.
    }

    @Test
    fun simple() {
        val t = SimpleVectors()
        val n = t.getNetworkAt()

        println("Network contains " + n.nodes.size + " nodes with " + n.numberOfEdges + " edges built from " + n.numberOfSignatures + " signatures.")
        println(n)

        val q = Query(n, Roots(), false)

        val a1 = q.backwardPropagate(t.ellenFpr, t.ellenUid)
        checkResult(a1[t.daveFpr]!!, 1, 100, listOf(t.daveFpr, t.ellenFpr));
        checkResult(a1[t.carolFpr]!!, 0, 100, listOf(t.carolFpr, t.daveFpr, t.ellenFpr));

        val a2 = q.backwardPropagate(t.daveFpr, t.daveUid);
        assertNull(a2[t.ellenFpr]);
        checkResult(a2[t.carolFpr]!!, 1, 100, listOf(t.carolFpr, t.daveFpr));
        checkResult(a2[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.carolFpr, t.daveFpr));
        checkResult(a2[t.aliceFpr]!!, 0, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr));

        val a3 = q.backwardPropagate(t.daveFpr, t.daveUid);
        assertNull(a3[t.ellenFpr]);
        checkResult(a3[t.carolFpr]!!, 1, 100, listOf(t.carolFpr, t.daveFpr));
        checkResult(a3[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.carolFpr, t.daveFpr));

        // This should work even though Bob is the root and the path is via Bob.
        checkResult(a3[t.aliceFpr]!!, 0, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr));

        val a4 = q.backwardPropagate(t.daveFpr, t.daveUid);
        assertNull(a4[t.ellenFpr])
        checkResult(a4[t.carolFpr]!!, 1, 100, listOf(t.carolFpr, t.daveFpr));

        // This should work even though Carol is the root is the path is via Carol.
        checkResult(a4[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.carolFpr, t.daveFpr));
        checkResult(a4[t.aliceFpr]!!, 0, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr));

        // Try to authenticate dave's key for a User ID that no one has certified.
        val a5 = q.backwardPropagate(t.daveFpr, t.ellenUid);
        assertNull(a5[t.ellenFpr]);
        assertNull(a5[t.daveFpr]);
        assertNull(a5[t.carolFpr]);
        assertNull(a5[t.bobFpr]);
        assertNull(a5[t.aliceFpr]);

        // A target that is not in the network.
        val fpr = Fingerprint("0123456789ABCDEF0123456789ABCDEF01234567")
        val a6 = q.backwardPropagate(fpr, t.ellenUid);
        assertNull(a6[t.ellenFpr]);
        assertNull(a6[t.daveFpr]);
        assertNull(a6[t.carolFpr]);
        assertNull(a6[t.bobFpr]);
        assertNull(a6[t.aliceFpr]);
    }

    @Test
    fun cycle() {
        val t = CycleVectors()
        val n = t.getNetworkAt()

        println("Network contains " + n.nodes.size + " nodes with " + n.numberOfEdges + " edges built from " + n.numberOfSignatures + " signatures.")
        println(n)

        val q = Query(n, Roots(), false)

        val a1 = q.backwardPropagate(t.frankFpr, t.frankUid);
        checkResult(a1[t.edFpr]!!, 0, 120, listOf(t.edFpr, t.frankFpr));
        checkResult(a1[t.daveFpr]!!, 0, 30, listOf(t.daveFpr, t.edFpr, t.frankFpr));
        checkResult(a1[t.carolFpr]!!, 0, 30, listOf(t.carolFpr, t.daveFpr, t.edFpr, t.frankFpr));
        checkResult(a1[t.bobFpr]!!, 0, 30, listOf(t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr, t.frankFpr));
        assertNull(a1[t.aliceFpr])

        val a2 = q.backwardPropagate(t.frankFpr, t.frankUid);
        checkResult(a2[t.edFpr]!!, 0, 120, listOf(t.edFpr, t.frankFpr));
        checkResult(a2[t.daveFpr]!!, 0, 30, listOf(t.daveFpr, t.edFpr, t.frankFpr));
        checkResult(a2[t.carolFpr]!!, 0, 30, listOf(t.carolFpr, t.daveFpr, t.edFpr, t.frankFpr));
        checkResult(a2[t.bobFpr]!!, 0, 30, listOf(t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr, t.frankFpr));
        assertNull(a2[t.aliceFpr])

        val a3 = q.backwardPropagate(t.edFpr, t.edUid);
        assertNull(a3[t.frankFpr])
        checkResult(a3[t.daveFpr]!!, 1, 30, listOf(t.daveFpr, t.edFpr));
        checkResult(a3[t.carolFpr]!!, 1, 30, listOf(t.carolFpr, t.daveFpr, t.edFpr));
        checkResult(a3[t.bobFpr]!!, 1, 30, listOf(t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr));
        checkResult(a3[t.aliceFpr]!!, 0, 30, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr));

        val a4 = q.backwardPropagate(t.carolFpr, t.carolUid);
        assertNull(a4[t.frankFpr]);
        assertNull(a4[t.edFpr]);
        checkResult(a4[t.daveFpr]!!, DEPTH_UNCONSTRAINED, 90, listOf(t.daveFpr, t.bobFpr, t.carolFpr));
        checkResult(a4[t.bobFpr]!!, DEPTH_UNCONSTRAINED, 90, listOf(t.bobFpr, t.carolFpr));

        // The backward propagation algorithm doesn't know that alice
        // is not reachable from the root (dave).
        checkResult(a4[t.aliceFpr]!!, 2, 90, listOf(t.aliceFpr, t.bobFpr, t.carolFpr));
    }

    @Test
    fun cliques() {
        val t1 = CliquesVectors()
        val n1 = t1.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)
        val a1 = q1.backwardPropagate(t1.targetFpr, t1.targetUid);

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        checkResult(a1[t1.rootFpr]!!, 90, 120,
                listOf(t1.rootFpr,
                        t1.a0Fpr,
                        t1.a1Fpr,
                        t1.b0Fpr,
                        t1.b1Fpr,
                        t1.c0Fpr,
                        t1.c1Fpr,
                        t1.d0Fpr,
                        t1.d1Fpr,
                        t1.e0Fpr,
                        t1.f0Fpr,
                        t1.targetFpr));

        val t2 = CliquesLocalOptimaVectors()
        val n2 = t2.getNetworkAt()

        println("Network contains " + n2.nodes.size + " nodes with " + n2.numberOfEdges + " edges built from " + n2.numberOfSignatures + " signatures.")
        println(n2)

        val q2 = Query(n2, Roots(), false)
        val a2 = q2.backwardPropagate(t2.targetFpr, t2.targetUid);

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        checkResult(a2[t2.rootFpr]!!,
                93, 30,
                listOf(t2.rootFpr,
                        t2.b0Fpr,
                        t2.b1Fpr,
                        t2.c0Fpr,
                        t2.c1Fpr,
                        t2.d0Fpr,
                        t2.d1Fpr,
                        t2.e0Fpr,
                        t2.f0Fpr,
                        t2.targetFpr));

        val t3 = CliquesLocalOptima2Vectors()
        val n3 = t3.getNetworkAt()

        println("Network contains " + n3.nodes.size + " nodes with " + n3.numberOfEdges + " edges built from " + n3.numberOfSignatures + " signatures.")
        println(n3)

        val q3 = Query(n3, Roots(), false)
        val a3 = q3.backwardPropagate(t3.targetFpr, t3.targetUid);

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        checkResult(a3[t3.rootFpr]!!, 94, 30,
                listOf(t3.rootFpr,
                        t3.b0Fpr,
                        t3.b1Fpr,
                        t3.c1Fpr,
                        t3.d0Fpr,
                        t3.d1Fpr,
                        t3.e0Fpr,
                        t3.f0Fpr,
                        t3.targetFpr));
    }

    @Test
    fun roundabout() {
        val t = RoundaboutVectors()
        val n = t.getNetworkAt()

        println("Network contains " + n.nodes.size + " nodes with " + n.numberOfEdges + " edges built from " + n.numberOfSignatures + " signatures.")
        println(n)

        val q1 = Query(n, Roots(), false)
        val a1 = q1.backwardPropagate(t.isaacFpr, t.isaacUid);

        checkResult(a1[t.aliceFpr]!!, 0, 60, listOf(t.aliceFpr, t.bobFpr, t.georgeFpr, t.henryFpr, t.isaacFpr));
        assertNull(a1[t.carolFpr])
        assertNull(a1[t.jennyFpr])

        val a2 = q1.backwardPropagate(t.henryFpr, t.henryUid);

        // The backward propagation algorithm doesn't know that jenny
        // is not reachable from the root (alice).
        checkResult(a2[t.jennyFpr]!!, 0, 100, listOf(t.jennyFpr, t.georgeFpr, t.henryFpr));
    }

    @Test
    fun localOptima() {
        val t = LocalOptimaVectors()
        val n = t.getNetworkAt()

        println("Network contains " + n.nodes.size + " nodes with " + n.numberOfEdges + " edges built from " + n.numberOfSignatures + " signatures.")
        println(n)

        val q = Query(n, Roots(), false)

        val a1 = q.backwardPropagate(t.henryFpr, t.henryUid);
        checkResult(a1[t.aliceFpr]!!, 0, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.ellenFpr, t.henryFpr));
        checkResult(a1[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.carolFpr, t.ellenFpr, t.henryFpr));
        checkResult(a1[t.carolFpr]!!, 0, 100, listOf(t.carolFpr, t.ellenFpr, t.henryFpr));
        checkResult(a1[t.daveFpr]!!, 0, 50, listOf(t.daveFpr, t.ellenFpr, t.henryFpr));
        checkResult(a1[t.ellenFpr]!!, 0, 120, listOf(t.ellenFpr, t.henryFpr));
        assertNull(a1[t.francisFpr])
        assertNull(a1[t.georginaFpr])

        val a2 = q.backwardPropagate(t.francisFpr, t.francisUid);

        // Recall: given a choice, we prefer the forward pointer that has the least depth.
        checkResult(a2[t.aliceFpr]!!, 149, 75, listOf(t.aliceFpr, t.bobFpr, t.francisFpr));
        checkResult(a2[t.bobFpr]!!, 200, 75, listOf(t.bobFpr, t.francisFpr));
        checkResult(a2[t.carolFpr]!!, 49, 100, listOf(t.carolFpr, t.ellenFpr, t.francisFpr));
        checkResult(a2[t.daveFpr]!!, 99, 50, listOf(t.daveFpr, t.ellenFpr, t.francisFpr));
        checkResult(a2[t.ellenFpr]!!, 100, 120, listOf(t.ellenFpr, t.francisFpr));
        assertNull(a2[t.georginaFpr])
        assertNull(a2[t.henryFpr])
    }

    @Test
    fun bestViaRoot() {
        val t = BestViaRootVectors()
        val n = t.getNetworkAt()

        println("Network contains " + n.nodes.size + " nodes with " + n.numberOfEdges + " edges built from " + n.numberOfSignatures + " signatures.")
        println(n)

        val q1 = Query(n, Roots(), false)

        val a1 = q1.backwardPropagate(t.targetFpr, t.targetUid);

        checkResult(a1[t.bobFpr]!!, 9, 120, listOf(t.bobFpr, t.carolFpr, t.targetFpr));
        checkResult(a1[t.carolFpr]!!, 10, 120, listOf(t.carolFpr, t.targetFpr));
        checkResult(a1[t.aliceFpr]!!, 8, 120, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.targetFpr));

        val a2 = q1.backwardPropagate(t.targetFpr, t.targetUid);

        checkResult(a2[t.aliceFpr]!!, 8, 120, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.targetFpr));
        checkResult(a2[t.bobFpr]!!, 9, 120, listOf(t.bobFpr, t.carolFpr, t.targetFpr));
        checkResult(a2[t.carolFpr]!!, 10, 120, listOf(t.carolFpr, t.targetFpr));


        // Again, but this time we specify the roots.
        val q2 = Query(n, Roots(listOf(Root(t.aliceFpr, 120))), false)
        val a3 = q2.backwardPropagate(t.targetFpr, t.targetUid);

        checkResult(a3[t.aliceFpr]!!, 8, 120, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.targetFpr));

        // As seen above, the best path from alice to the target is via bob. But when both alice and bob are both fully
        // trusted roots, the returned path is not via bob, but one that is less optimal.
        val q3 = Query(n, Roots(listOf(Root(t.aliceFpr), Root(t.bobFpr))), false)
        val a4 = q3.backwardPropagate(t.targetFpr, t.targetUid);

        checkResult(a4[t.bobFpr]!!, 9, 120, listOf(t.bobFpr, t.carolFpr, t.targetFpr));
        checkResult(a4[t.aliceFpr]!!, 8, 50, listOf(t.aliceFpr, t.yellowFpr, t.zebraFpr, t.targetFpr));
    }

    @Test
    fun regex1() {
        val t = Regex1Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " t.edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)

        // alice as root.
        val a1 = q1.backwardPropagate(t.bobFpr, t.bobUid);
        checkResult(a1[t.aliceFpr]!!, 3, 100, listOf(t.aliceFpr, t.bobFpr));

        val a2 = q1.backwardPropagate(t.carolFpr, t.carolUid);
        checkResult(a2[t.aliceFpr]!!, 1, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr));

        val a3 = q1.backwardPropagate(t.daveFpr, t.daveUid);

        // There is no path, because t.dave@example.org does not match the constraint on t.bob (domain: example.org).
        assertNull(a3[t.aliceFpr])

        val a4 = q1.backwardPropagate(t.edFpr, t.edUid)

        // There is no path, because t.ed@example.org does not match the constraint on t.dave (domain: other.org).
        assertNull(a4[t.aliceFpr])

        val a5 = q1.backwardPropagate(t.frankFpr, t.frankUid)

        // There is no path, because t.frank@other.org does not match the constraint on t.bob (domain: example.org).
        assertNull(a5[t.aliceFpr])


        // bob as root.
        val a6 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        checkResult(a6[t.bobFpr]!!, 1, 100, listOf(t.bobFpr, t.carolFpr))

        val a7 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a7[t.bobFpr]!!, 1, 100, listOf(t.bobFpr, t.daveFpr))

        val a8 = q1.backwardPropagate(t.edFpr, t.edUid)
        // There is no path, because t.ed@example.org does not match the constraint on t.dave (domain: other.org).
        assertNull(a8[t.bobFpr])

        val a9 = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(a9[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.daveFpr, t.frankFpr))

        // dave as root.
        val a10 = q1.backwardPropagate(t.edFpr, t.edUid)
        checkResult(a10[t.daveFpr]!!, 1, 100, listOf(t.daveFpr, t.edFpr));

        val a11 = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(a11[t.daveFpr]!!, 1, 100, listOf(t.daveFpr, t.frankFpr))
    }

    @Test
    fun regex2() {
        val t = Regex2Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " t.edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)

        val a1 = q1.backwardPropagate(t.bobFpr, t.bobUid)
        checkResult(a1[t.aliceFpr]!!, 7, 100, listOf(t.aliceFpr, t.bobFpr))

        val a2 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        // There is no path, because carol@other.org does not match the constraint on carol (domain: example.org).
        assertNull(a2[t.aliceFpr])

        val a3 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        // There is no path, because dave@their.org does not match the constraint on carol (domain: example.org).
        assertNull(a3[t.aliceFpr])

        val a4 = q1.backwardPropagate(t.edFpr, t.edUid)
        checkResult(a4[t.aliceFpr]!!, 4, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr))

        val a5 = q1.backwardPropagate(t.carolFpr, t.carolUid);
        // There is no path, because carol@other.org does not match
        // the constraint on carol (domain: example.org).
        assertNull(a5[t.bobFpr])

        val a6 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        // There is no path, because dave@their.org does not match the constraint on carol (domain: example.org).
        assertNull(a6[t.bobFpr])

        val a7 = q1.backwardPropagate(t.edFpr, t.edUid)
        checkResult(a7[t.bobFpr]!!, 5, 100, listOf(t.bobFpr, t.carolFpr, t.daveFpr, t.edFpr))

        val a8 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a8[t.carolFpr]!!, 7, 100, listOf(t.carolFpr, t.daveFpr));

        val a9 = q1.backwardPropagate(t.edFpr, t.edUid)
        checkResult(a9[t.carolFpr]!!, 6, 100, listOf(t.carolFpr, t.daveFpr, t.edFpr))
    }

    @Test
    fun regex3() {
        val t = Regex3Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " t.edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)

        // alice as root.
        val a1 = q1.backwardPropagate(t.bobFpr, t.bobUid)
        checkResult(a1[t.aliceFpr]!!, 3, 100, listOf(t.aliceFpr, t.bobFpr))

        val a2 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        checkResult(a2[t.aliceFpr]!!, 1, 100, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))

        val a3 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a3[t.aliceFpr]!!, 1, 100, listOf(t.aliceFpr, t.bobFpr, t.daveFpr))

        val a4 = q1.backwardPropagate(t.edFpr, t.edUid)
        // There is no path, because ed@example.org does not match the constraint on dave (domain: other.org).
        assertNull(a4[t.aliceFpr])

        val a5 = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(a5[t.aliceFpr]!!, 0, 100, listOf(t.aliceFpr, t.bobFpr, t.daveFpr, t.frankFpr))

        val a6 = q1.backwardPropagate(t.georgeFpr, t.georgeUid)
        assertNull(a6[t.aliceFpr])

        val a7 = q1.backwardPropagate(t.henryFpr, t.henryUid)
        assertNull(a7[t.aliceFpr])


        // bob as root.
        val a8 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        checkResult(a8[t.bobFpr]!!, 1, 100, listOf(t.bobFpr, t.carolFpr))

        val a9 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a9[t.bobFpr]!!, 1, 100, listOf(t.bobFpr, t.daveFpr))

        val a10 = q1.backwardPropagate(t.edFpr, t.edUid)
        // There is no path, because ed@example.org does not match the constraint on dave (domain: other.org).
        assertNull(a10[t.bobFpr])

        val a11 = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(a11[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.daveFpr, t.frankFpr))

        val a12 = q1.backwardPropagate(t.georgeFpr, t.georgeUid)
        checkResult(a12[t.bobFpr]!!, 0, 100, listOf(t.bobFpr, t.daveFpr, t.georgeFpr))

        val a13 = q1.backwardPropagate(t.henryFpr, t.henryUid)
        checkResult(a13[t.bobFpr]!!, 1, 100, listOf(t.bobFpr, t.henryFpr))


        // dave as root.
        val a14 = q1.backwardPropagate(t.edFpr, t.edUid)
        checkResult(a14[t.daveFpr]!!, 1, 100, listOf(t.daveFpr, t.edFpr))

        val a15 = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(a15[t.daveFpr]!!, 1, 100, listOf(t.daveFpr, t.frankFpr))

        val a16 = q1.backwardPropagate(t.georgeFpr, t.georgeUid)
        checkResult(a16[t.daveFpr]!!, 1, 100, listOf(t.daveFpr, t.georgeFpr))
    }

    @Test
    fun multipleUserids1() {
        val t = MultipleUserIds1Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " t.edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)

        val a1 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        checkResult(a1[t.aliceFpr]!!, 0, 70, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))

        val a2 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a2[t.aliceFpr]!!, 0, 50, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr))
    }

    @Test
    fun multipleUserids2() {
        val t = MultipleUserIds2Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " t.edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)


        val a1 = q1.backwardPropagate(t.bobFpr, t.bobUid)
        checkResult(a1[t.aliceFpr]!!, DEPTH_UNCONSTRAINED, 70, listOf(t.aliceFpr, t.bobFpr))

        val a2 = q1.backwardPropagate(t.bobFpr, t.bobSomeOrgUid)
        checkResult(a2[t.aliceFpr]!!, 1, 50, listOf(t.aliceFpr, t.bobFpr))

        val a3 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        checkResult(a3[t.aliceFpr]!!, 0, 50, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))

        val a4 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a4[t.aliceFpr]!!, 0, 70, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr))

        val a5 = q1.backwardPropagate(t.edFpr, t.edUid)
        assertNull(a5[t.aliceFpr])

        val a6 = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(a6[t.aliceFpr]!!, 0, 70, listOf(t.aliceFpr, t.bobFpr, t.frankFpr))
    }

    @Test
    fun multipleUserids3() {
        val t = MultipleUserIds3Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)

        val auth = q1.backwardPropagate(t.frankFpr, t.frankUid)
        checkResult(auth[t.aliceFpr]!!, 0, 20, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.frankFpr))
    }

    @Test
    fun multipleCertifications1() {
        val t = MultipleCertifications1Vectors()
        val n1 = t.getNetworkAt()

        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")
        println(n1)

        val q1 = Query(n1, Roots(), false)

        val a1 = q1.backwardPropagate(t.carolFpr, t.carolUid)
        checkResult(a1[t.aliceFpr]!!, 0, 70, listOf(t.aliceFpr, t.bobFpr, t.carolFpr))

        val a2 = q1.backwardPropagate(t.daveFpr, t.daveUid)
        checkResult(a2[t.aliceFpr]!!, 0, 50, listOf(t.aliceFpr, t.bobFpr, t.carolFpr, t.daveFpr))
    }
}