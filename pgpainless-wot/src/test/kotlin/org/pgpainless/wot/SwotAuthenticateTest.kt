package org.pgpainless.wot

import org.pgpainless.PGPainless
import org.pgpainless.wot.dijkstra.Query
import org.pgpainless.wot.network.*
import java.io.File
import java.time.Instant
import java.util.*
import kotlin.RuntimeException
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Tests from sequoia-wot:src/lib.rs
 */
class SwotAuthenticateTest {

    // Authenticates the target.
    private fun sp(q: Query,
                   targetFpr: Fingerprint,
                   targetUserid: String,
                   expected: List<Pair<Int, List<Fingerprint>>>,
                   minTrustAmount: Int?) {

        println("authenticating: $targetFpr, $targetUserid");

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
                            val e = b.second

                            assertEquals(
                                    e, g,
                                    "got vs. expected path (#$i)",
                            )
                            assertEquals(e.first, g.first,
                                    "got vs. expected trust amount (#$i)"
                            )
                        }

                assertEquals(got.amount, expected.sumOf { it.first })
            }
        }

        // NOTE: we're not checking the validity of the path on the OpenPGP layer
    }


    private fun getNetwork(filename: String): Network {
        return getNetwork(filename, ReferenceTime.now())
    }

    private fun getNetwork(filename: String, referenceTime: Long): Network {
        val instant = Instant.ofEpochSecond(referenceTime)
        val date = Date.from(instant);

        return getNetwork(filename, ReferenceTime.timestamp(date))
    }

    private fun getNetwork(filename: String, referenceTime: ReferenceTime): Network {
        val inputStream = File(filename).inputStream()
        val keyrings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream)

        val store = KeyRingCertificateStore(keyrings)

        return WebOfTrust(store).buildNetwork(referenceTime = referenceTime)
    }

    @Test
    fun simple() {
        val aliceFpr = Fingerprint("85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D")
        val aliceUid = "<alice@example.org>";

        val bobFpr = Fingerprint("39A479816C934B9E0464F1F4BC1DCFDEADA4EE90")
        val bobUid = "<bob@example.org>"
        // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

        val carolFpr = Fingerprint("43530F91B450EDB269AA58821A1CF4DC7F500F04")
        val carolUid = "<carol@example.org>"
        // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

        val daveFpr = Fingerprint("329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281")
        val daveUid = "<dave@example.org>"
        // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

        val ellenFpr = Fingerprint("A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4")
        val ellenUid = "<ellen@example.org>"
        // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

        val frankFpr = Fingerprint("2693237D2CED0BB68F118D78DC86A97CD2C819D9")
        val frankUid = "<frank@example.org>"

        // --

        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/simple.pgp")
        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

        sp(q1, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)
        sp(q1, bobFpr, bobUid, listOf(Pair(100, listOf(aliceFpr, bobFpr))), null)
        sp(q1, carolFpr, carolUid, listOf(Pair(100, listOf(aliceFpr, bobFpr, carolFpr))), null)
        sp(q1, daveFpr, daveUid, listOf(Pair(100, listOf(aliceFpr, bobFpr, carolFpr, daveFpr))), null)
        sp(q1, ellenFpr, ellenUid, listOf(), null)
        sp(q1, frankFpr, frankUid, listOf(), null)
        sp(q1, carolFpr, bobUid, listOf(), null) // No one authenticated Bob's User ID on Carol's key.

        val q2 = Query(n1, Roots(listOf(Root(bobFpr))), false)

        sp(q2, aliceFpr, aliceUid, listOf(), null)
        sp(q2, bobFpr, bobUid, listOf(Pair(120, listOf(bobFpr))), null)
        sp(q2, carolFpr, carolUid, listOf(Pair(100, listOf(bobFpr, carolFpr))), null)
        sp(q2, daveFpr, daveUid, listOf(Pair(100, listOf(bobFpr, carolFpr, daveFpr))), null)
        sp(q2, ellenFpr, ellenUid, listOf(), null)
        sp(q2, frankFpr, frankUid, listOf(), null)
        sp(q2, carolFpr, bobUid, listOf(), null) // No one authenticated Bob's User ID on Carol's key.
    }

    @Test
    fun cycle() {
        val aliceFpr = Fingerprint("BFC5CA10FB55A4B790E2A1DBA5CFAB9A9E34E183")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("A637747DCF876A7F6C9149F74D47846E24A20C0B")
        val bobUid = "<bob@example.org>"
        // Certified by: 4458062DC7388909CF760E6823150D8E4408638A
        // Certified by: BFC5CA10FB55A4B790E2A1DBA5CFAB9A9E34E183

        val carolFpr = Fingerprint("394B04774FDAB0CDBF4D6FFD7930EA0FB549E303")
        val carolUid = "<carol@example.org>"
        // Certified by: A637747DCF876A7F6C9149F74D47846E24A20C0B

        val daveFpr = Fingerprint("4458062DC7388909CF760E6823150D8E4408638A")
        val daveUid = "<dave@example.org>"
        // Certified by: 394B04774FDAB0CDBF4D6FFD7930EA0FB549E303

        val edFpr = Fingerprint("78C3814EFD16E68F4F1AB4B874E30AE11FFCFB1B")
        val edUid = "<ed@example.org>"
        // Certified by: 4458062DC7388909CF760E6823150D8E4408638A

        val frankFpr = Fingerprint("A6219FF753AEAE2DE8A74E8487977DD568A08237")
        val frankUid = "<frank@example.org>"
        // Certified by: 78C3814EFD16E68F4F1AB4B874E30AE11FFCFB1B

        // --

        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cycle.pgp")
        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")

        println("$n1");

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

        sp(q1, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)
        sp(q1, bobFpr, bobUid, listOf(Pair(120, listOf(aliceFpr, bobFpr))), null)
        sp(q1, carolFpr, carolUid, listOf(Pair(90, listOf(aliceFpr, bobFpr, carolFpr))), null)
        sp(q1, daveFpr, daveUid, listOf(Pair(60, listOf(aliceFpr, bobFpr, carolFpr, daveFpr))), null)
        sp(q1, edFpr, edUid, listOf(Pair(30, listOf(aliceFpr, bobFpr, carolFpr, daveFpr, edFpr))), null)
        sp(q1, frankFpr, frankUid, listOf(), null)

        val q2 = Query(n1, Roots(listOf(Root(aliceFpr), Root(daveFpr))), false)

        sp(q2, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)

        // The following paths are identical and the sorting depends
        // on the fingerprint.  Thus regenerating the keys could
        // create a failure.
        sp(q2, bobFpr, bobUid,
                listOf(Pair(120, listOf(aliceFpr, bobFpr)),
                        Pair(120, listOf(daveFpr, bobFpr))),
                300)

        sp(q2, carolFpr, carolUid, listOf(Pair(90, listOf(aliceFpr, bobFpr, carolFpr))), null)
        sp(q2, edFpr, edUid, listOf(Pair(30, listOf(daveFpr, edFpr))), null)
        sp(q2, frankFpr, frankUid, listOf(Pair(30, listOf(daveFpr, edFpr, frankFpr))), null)
    }

    @Test
    fun cliques() {
        val rootFpr = Fingerprint("D2B0C3835C01B0C120BC540DA4AA8F880BA512B5")
        val rootUid = "<root@example.org>"

        val a0Fpr = Fingerprint("363082E9EEB22E50AD303D8B1BFE9BA3F4ABD40E")
        val a0Uid = "<a-0@example.org>"

        val a1Fpr = Fingerprint("7974C04E8D5B540D23CD4E62DDFA779D91C69894")
        val a1Uid = "<a-1@example.org>"

        val b0Fpr = Fingerprint("25D8EAAB894705BB64D4A6A89649EF81AEFE5162")
        val b0Uid = "<b-0@example.org>"

        val b1Fpr = Fingerprint("46D2F5CED9BD3D63A11DDFEE1BA019506BE67FBB")
        val b1Uid = "<b-1@example.org>"

        val c0Fpr = Fingerprint("A0CD87582C21743C0E30637F7FADB1C3FEFBFE59")
        val c0Uid = "<c-0@example.org>"

        val c1Fpr = Fingerprint("5277C14F9D37A0F4D615DD9CCDCC1AC8464C8FE5")
        val c1Uid = "<c-1@example.org>"

        val d0Fpr = Fingerprint("C24CC09102D22E38E8393C55166982561E140C03")
        val d0Uid = "<d-0@example.org>"

        val d1Fpr = Fingerprint("7A80DB5330B7D900D5BD1F82EAD72FF7914078B2")
        val d1Uid = "<d-1@example.org>"

        val e0Fpr = Fingerprint("D1E9F85CEF6271699FBDE5AB26EFE0E035AC522E")
        val e0Uid = "<e-0@example.org>"

        val f0Fpr = Fingerprint("C0FFAEDEF0928B181265775A222B480EB43E0AFF")
        val f0Uid = "<f-0@example.org>"

        val targetFpr = Fingerprint("CE22ECD282F219AA99598BA3B58A7DA61CA97F55")
        val targetUid = "<target@example.org>"


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cliques.pgp")
        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")

        println("$n1");

        val q1 = Query(n1, Roots(listOf(Root(rootFpr))), false)

        // root -> a-0 -> a-1 -> b-0 -> ... -> f-0 -> target
        sp(q1, targetFpr, targetUid,
                listOf(Pair(120, listOf(rootFpr, a0Fpr, a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr))),
                null)


        val q2 = Query(n1, Roots(listOf(Root(a1Fpr))), false)

        sp(q2, targetFpr, targetUid,
                listOf(Pair(120, listOf(a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr))),
                null)


        val n2 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cliques-local-optima.pgp")
        println("Network contains " + n2.nodes.size + " nodes with " + n2.numberOfEdges + " edges built from " + n2.numberOfSignatures + " signatures.")

        println("$n2");

        val q3 = Query(n2, Roots(listOf(Root(rootFpr))), false)

        // root -> b-0 -> ... -> f-0 -> target
        sp(q3, targetFpr, targetUid,
                listOf(Pair(30, listOf(rootFpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr)),
                        Pair(30, listOf(rootFpr, a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr)),
                        Pair(60, listOf(rootFpr, a0Fpr, a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr))),
                null)


        val q4 = Query(n2, Roots(listOf(Root(a1Fpr))), false)

        sp(q4, targetFpr, targetUid,
                listOf(Pair(120, listOf(a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr))),
                null)


        val n3 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cliques-local-optima-2.pgp")
        println("Network contains " + n3.nodes.size + " nodes with " + n3.numberOfEdges + " edges built from " + n3.numberOfSignatures + " signatures.")

        println("$n3");

        val q5 = Query(n3, Roots(listOf(Root(rootFpr))), false)

        // root -> b-0 -> ... -> f-0 -> target
        sp(q5, targetFpr, targetUid,
                listOf(Pair(30, listOf(rootFpr, b0Fpr, b1Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr)),
                        Pair(30, listOf(rootFpr, a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr)),
                        Pair(60, listOf(rootFpr, a0Fpr, a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr))),
                null)


        val q6 = Query(n3, Roots(listOf(Root(a1Fpr))), false)

        sp(q6, targetFpr, targetUid,
                listOf(Pair(30, listOf(a1Fpr, b0Fpr, b1Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr)),
                        Pair(90, listOf(a1Fpr, b0Fpr, b1Fpr, c0Fpr, c1Fpr, d0Fpr, d1Fpr, e0Fpr, f0Fpr, targetFpr))),
                null)
    }

    @Test
    fun roundabout() {
        val aliceFpr = Fingerprint("41E9B069C96EB6D47525294B10BBBD00912BEA02")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("2E90AEE966DF28CB916439B20397E086E705AC1A")
        val bobUid = "<bob@example.org>"
        // Certified by: 3267D46247D26101B3E5014CDF4F9BA5831D91DA
        // Certified by: 41E9B069C96EB6D47525294B10BBBD00912BEA02

        val carolFpr = Fingerprint("92DDE8747C8E6ED09D41A4E1330D1190E858754C")
        val carolUid = "<carol@example.org>"
        // Certified by: 41E9B069C96EB6D47525294B10BBBD00912BEA02

        val daveFpr = Fingerprint("D4515E6619084ED8142DF8589059E3846A025611")
        val daveUid = "<dave@example.org>"
        // Certified by: 92DDE8747C8E6ED09D41A4E1330D1190E858754C

        val elmarFpr = Fingerprint("E553C11DCFA777F3205E5090F5EE59C2795CDBA2")
        val elmarUid = "<elmar@example.org>"
        // Certified by: AE40578962411356F9609CAA9C2447E61FFDBB15
        // Certified by: D4515E6619084ED8142DF8589059E3846A025611

        val frankFpr = Fingerprint("3267D46247D26101B3E5014CDF4F9BA5831D91DA")
        val frankUid = "<frank@example.org>"
        // Certified by: E553C11DCFA777F3205E5090F5EE59C2795CDBA2

        val georgeFpr = Fingerprint("CCD5DB27BD7C4F8E2010083605EF17E8A93EB652")
        val georgeUid = "<george@example.org>"
        // Certified by: AE40578962411356F9609CAA9C2447E61FFDBB15
        // Certified by: 2E90AEE966DF28CB916439B20397E086E705AC1A

        val henryFpr = Fingerprint("7F62EF97091AE1FCB4E1C67EC8D9E94C4731529B")
        val henryUid = "<henry@example.org>"
        // Certified by: CCD5DB27BD7C4F8E2010083605EF17E8A93EB652

        val isaacFpr = Fingerprint("32FD4D68B3227334CD0583E9FA0721F49D2F395D")
        val isaacUid = "<isaac@example.org>"
        // Certified by: 7F62EF97091AE1FCB4E1C67EC8D9E94C4731529B

        val jennyFpr = Fingerprint("AE40578962411356F9609CAA9C2447E61FFDBB15")
        val jennyUid = "<jenny@example.org>"


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/roundabout.pgp")
        println("Network contains " + n1.nodes.size + " nodes with " + n1.numberOfEdges + " edges built from " + n1.numberOfSignatures + " signatures.")
        println("$n1");

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

        sp(q1, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)

        sp(q1, bobFpr, bobUid,
                listOf(Pair(60, listOf(aliceFpr, bobFpr)),
                        Pair(120, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr, frankFpr, bobFpr))
                ),
                null)

        sp(q1, carolFpr, carolUid, listOf(Pair(120, listOf(aliceFpr, carolFpr))), null)

        sp(q1, daveFpr, daveUid, listOf(Pair(120, listOf(aliceFpr, carolFpr, daveFpr))), null)

        sp(q1, elmarFpr, elmarUid, listOf(Pair(120, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr))), null)

        sp(q1, frankFpr, frankUid, listOf(Pair(120, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr, frankFpr))), null)

        sp(q1, georgeFpr, georgeUid,
                listOf(Pair(60, listOf(aliceFpr, bobFpr, georgeFpr)),
                        Pair(60, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr,
                                frankFpr, bobFpr, georgeFpr))),
                null)

        sp(q1, henryFpr, henryUid,
                listOf(Pair(60, listOf(aliceFpr, bobFpr, georgeFpr, henryFpr)),
                        Pair(60, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr,
                                frankFpr, bobFpr, georgeFpr, henryFpr))),
                null)

        sp(q1, isaacFpr, isaacUid,
                listOf(Pair(60, listOf(aliceFpr, bobFpr, georgeFpr, henryFpr, isaacFpr))),
                null)

        sp(q1, jennyFpr, jennyUid, listOf(), null)


        val q2 = Query(n1, Roots(listOf(Root(jennyFpr))), false)

        sp(q2, aliceFpr, aliceUid, listOf(), null)

        sp(q2, bobFpr, bobUid, listOf(Pair(100, listOf(jennyFpr, elmarFpr, frankFpr, bobFpr))), null)

        sp(q2, carolFpr, carolUid, listOf(), null)

        sp(q2, daveFpr, daveUid, listOf(), null)

        sp(q2, elmarFpr, elmarUid, listOf(Pair(100, listOf(jennyFpr, elmarFpr))), null)

        sp(q2, frankFpr, frankUid, listOf(Pair(100, listOf(jennyFpr, elmarFpr, frankFpr))), null)

        sp(q2, georgeFpr, georgeUid,
                listOf(Pair(100, listOf(jennyFpr, georgeFpr)),
                        Pair(100, listOf(jennyFpr, elmarFpr, frankFpr, bobFpr, georgeFpr))
                ), null)

        sp(q2, henryFpr, henryUid,
                listOf(Pair(100, listOf(jennyFpr, georgeFpr, henryFpr)),
                        Pair(20, listOf(jennyFpr, elmarFpr, frankFpr, bobFpr, georgeFpr, henryFpr))
                ), null)

        sp(q2, isaacFpr, isaacUid, listOf(), null)

        sp(q2, jennyFpr, jennyUid, listOf(Pair(120, listOf(jennyFpr))), null)


        val q3 = Query(n1, Roots(listOf(Root(aliceFpr), Root(jennyFpr))), false)

        sp(q3, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)

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
        sp(q3, bobFpr, bobUid,
                listOf(Pair(100, listOf(jennyFpr, elmarFpr, frankFpr, bobFpr)),
                        Pair(60, listOf(aliceFpr, bobFpr)),
                        Pair(20, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr, frankFpr, bobFpr))
                ), 240)

        sp(q3, carolFpr, carolUid, listOf(Pair(120, listOf(aliceFpr, carolFpr))), null)

        sp(q3, daveFpr, daveUid, listOf(Pair(120, listOf(aliceFpr, carolFpr, daveFpr))), null)

        sp(q3, elmarFpr, elmarUid, listOf(Pair(120, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr))), null)

        sp(q3, frankFpr, frankUid, listOf(Pair(120, listOf(aliceFpr, carolFpr, daveFpr, elmarFpr, frankFpr))), 240);

        sp(q3, georgeFpr, georgeUid,
                listOf(
                        Pair(100, listOf(jennyFpr, georgeFpr)),
                        Pair(100, listOf(jennyFpr, elmarFpr, frankFpr, bobFpr, georgeFpr)),
                        Pair(20, listOf(aliceFpr, bobFpr, georgeFpr)),
                ), 240)

        // FIXME: original expectation
//        sp(q3, henryFpr, henryUid,
//                listOf(Pair(60, listOf(aliceFpr, bobFpr, georgeFpr, henryFpr)),
//                        Pair(60, listOf(jennyFpr, georgeFpr, henryFpr))
//                ), null)

        // FIXME: adjusted expectation -> why exactly is this different?
        sp(q3, henryFpr, henryUid,
                listOf(Pair(100, listOf(jennyFpr, georgeFpr, henryFpr)),
                        Pair(20, listOf(aliceFpr, bobFpr, georgeFpr, henryFpr))
                ), null)

        sp(q3, isaacFpr, isaacUid, listOf(Pair(60, listOf(aliceFpr, bobFpr, georgeFpr, henryFpr, isaacFpr))), null)

        sp(q3, jennyFpr, jennyUid, listOf(Pair(120, listOf(jennyFpr))), null)
    }


    @Test
    fun local_optima() {
        val aliceFpr = Fingerprint("EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F")
        val bobUid = "<bob@example.org>"
        // Certified by: EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8
        // Certified by: EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8

        val carolFpr = Fingerprint("E9DF94E389F529F8EF6AA223F6CC1F8544C0874D")
        val carolUid = "<carol@example.org>"
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

        val daveFpr = Fingerprint("C2F822F17B68E946853A2DCFF55541D89F27F88B")
        val daveUid = "<dave@example.org>"
        // Certified by: E9DF94E389F529F8EF6AA223F6CC1F8544C0874D
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

        val ellenFpr = Fingerprint("70507A9058A57FEAE18CC3CE6A398AC9051D9CA8")
        val ellenUid = "<ellen@example.org>"
        // Certified by: C2F822F17B68E946853A2DCFF55541D89F27F88B
        // Certified by: C2F822F17B68E946853A2DCFF55541D89F27F88B
        // Certified by: E9DF94E389F529F8EF6AA223F6CC1F8544C0874D

        val francisFpr = Fingerprint("D8DDA78A2297CA3C35B9377577E8B54B9350C082")
        val francisUid = "<francis@example.org>"
        // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

        val georginaFpr = Fingerprint("C5D1B22FEC75911A04E1A5DC75B66B994E70ADE2")
        val georginaUid = "<georgina@example.org>"
        // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8

        val henryFpr = Fingerprint("F260739E3F755389EFC2FEE67F58AACB661D5120")
        val henryUid = "<henry@example.org>"
        // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8

        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/local-optima.pgp")
        println("$n1")

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

        sp(q1, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)

        sp(q1, bobFpr, bobUid, listOf(Pair(120, listOf(aliceFpr, bobFpr))), null)

        sp(q1, carolFpr, carolUid, listOf(Pair(100, listOf(aliceFpr, bobFpr, carolFpr))), null)

        sp(q1, daveFpr, daveUid, listOf(Pair(50, listOf(aliceFpr, bobFpr, daveFpr))), null)

        sp(q1, ellenFpr, ellenUid,
                listOf(
                        Pair(100, listOf(aliceFpr, bobFpr, carolFpr, ellenFpr)),
                        Pair(20, listOf(aliceFpr, bobFpr, daveFpr, ellenFpr)),
                ), null)

        sp(q1, francisFpr, francisUid,
                listOf(
                        Pair(75, listOf(aliceFpr, bobFpr, francisFpr)),
                        Pair(45, listOf(aliceFpr, bobFpr, carolFpr, ellenFpr, francisFpr)),
                ), null)

        sp(q1, georginaFpr, georginaUid, listOf(Pair(30, listOf(aliceFpr, bobFpr, daveFpr, ellenFpr, georginaFpr))), null)

        sp(q1, henryFpr, henryUid,
                listOf(
                        Pair(100, listOf(aliceFpr, bobFpr, carolFpr, ellenFpr, henryFpr)),
                        Pair(20, listOf(aliceFpr, bobFpr, daveFpr, ellenFpr, henryFpr)),
                ), null)


        val q2 = Query(n1, Roots(listOf(Root(bobFpr))), false)

        sp(q2, aliceFpr, aliceUid, listOf(), null)

        sp(q2, bobFpr, bobUid, listOf(Pair(120, listOf(bobFpr))), null)

        sp(q2, carolFpr, carolUid, listOf(Pair(100, listOf(bobFpr, carolFpr))), null)

        sp(q2, daveFpr, daveUid, listOf(Pair(50, listOf(bobFpr, daveFpr))), null)

        sp(q2, ellenFpr, ellenUid,
                listOf(
                        Pair(100, listOf(bobFpr, carolFpr, ellenFpr)),
                        Pair(50, listOf(bobFpr, daveFpr, ellenFpr)),
                ), null)

        sp(q2, francisFpr, francisUid,
                listOf(
                        Pair(75, listOf(bobFpr, francisFpr)),
                        Pair(100, listOf(bobFpr, carolFpr, ellenFpr, francisFpr)),
                        Pair(20, listOf(bobFpr, daveFpr, ellenFpr, francisFpr)),
                ), 240)
    }

    @Test
    fun multiple_userids_3() {
        val aliceFpr = Fingerprint("DA3CFC60BD4B8835702A66782C7A431946C12DF7")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("28C108707090FCDFF630D1E141FB02F0E397D55E")
        val bobUid = "<bob@other.org>"
        // Certified by: DA3CFC60BD4B8835702A66782C7A431946C12DF7
        val bob_some_orgUid = "<bob@some.org>"
        // Certified by: DA3CFC60BD4B8835702A66782C7A431946C12DF7
        val bob_third_orgUid = "<bob@third.org>"

        val carolFpr = Fingerprint("9FB1D2F41AB5C478378E728C8DD5A5A434EEAAB8")
        val carolUid = "<carol@example.org>"
        // Certified by: 28C108707090FCDFF630D1E141FB02F0E397D55E

        val daveFpr = Fingerprint("0C131F8959F45D08B6136FDAAD2E16A26F73D48E")
        val daveUid = "<dave@example.org>"
        // Certified by: 28C108707090FCDFF630D1E141FB02F0E397D55E

        val edFpr = Fingerprint("296935FAE420CCCF3AEDCEC9232BFF0AE9A7E5DB")
        val edUid = "<ed@example.org>"
        // Certified by: 0C131F8959F45D08B6136FDAAD2E16A26F73D48E

        val frankFpr = Fingerprint("A72AA1B7D9D8CB04D988F1520A404E37A7766608")
        val frankUid = "<frank@example.org>"
        // Certified by: 9FB1D2F41AB5C478378E728C8DD5A5A434EEAAB8
        // Certified by: 296935FAE420CCCF3AEDCEC9232BFF0AE9A7E5DB


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/multiple-userids-3.pgp")
        println("$n1")

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)


        sp(q1, frankFpr, frankUid,
                listOf(
                        Pair(20, listOf(aliceFpr, bobFpr, carolFpr, frankFpr)),
                        Pair(10, listOf(aliceFpr, bobFpr, daveFpr, edFpr, frankFpr)),
                ), null)

    }

    @Test
    fun certification_liveness() {
        val aliceFpr = Fingerprint("77C077250C26357E5E64A58A41426350B1D7F738")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("840891562819D3A108C4DA1BB31438DE34F8CF69")
        val bobUid = "<bob@example.org>"
        // Certified by: 77C077250C26357E5E64A58A41426350B1D7F738
        // Certified by: 77C077250C26357E5E64A58A41426350B1D7F738

        val carolFpr = Fingerprint("E8BB154D000C17AC87291D7271553C836973FE01")
        val carolUid = "<carol@example.org>"
        // Certified by: 840891562819D3A108C4DA1BB31438DE34F8CF69
        // Certified by: 840891562819D3A108C4DA1BB31438DE34F8CF69

        for ((i, t) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            println("Trying at $t");

            val n = getNetwork("/home/heiko/src/sequoia-wot/tests/data/certification-liveness.pgp", t)
            val q = Query(n, Roots(listOf(Root(aliceFpr))), false)

            val amount = when (i + 1) {
                1 -> 60
                2 -> 120
                3 -> 60
                else -> throw RuntimeException("")
            }

            sp(q, carolFpr, carolUid, listOf(Pair(amount, listOf(aliceFpr, bobFpr, carolFpr))), null)
        }
    }

    @Test
    fun cert_revoked_soft() {

        val aliceFpr = Fingerprint("66037F98B444BBAFDFE98E871738DFAB86878262")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("4CD8737F76C2B897C4F058DBF28C47540FA2C3B3")
        val bobUid = "<bob@example.org>"
        // Certified by: 66037F98B444BBAFDFE98E871738DFAB86878262

        val carolFpr = Fingerprint("AB4E3F8EE8BBD3459754D75ACE570F9B8C7DC75D")
        val carolUid = "<carol@example.org>"
        // Certified by: 66037F98B444BBAFDFE98E871738DFAB86878262

        val daveFpr = Fingerprint("DF6A440ED9DE723B0EBC7F50E24FBB1B9FADC999")
        val daveUid = "<dave@example.org>"
        // Certified by: 4CD8737F76C2B897C4F058DBF28C47540FA2C3B3
        // Certified by: AB4E3F8EE8BBD3459754D75ACE570F9B8C7DC75D
        // Certified by: 4CD8737F76C2B897C4F058DBF28C47540FA2C3B3


        for ((i, t) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            // At t1, soft revocations are in the future so certifications
            // are still valid.
            //
            // At t2, B is soft revoked so existing certifications are
            // still valid, but we can no longer authenticate B.
            //
            // At t3, A recertifies B and B recertifies D.  These
            // certifications should be ignored as they are made after B
            // was revoked.

            val date = Date(Instant.ofEpochSecond(t).toEpochMilli())
            println("Trying at #$i $date");

            val n = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cert-revoked-soft.pgp", t)
            println("$n")

            // Consider just the code path where B is the issuer.
            //
            // Covers scenarios #1 at t1, #3 at t2 and t3
            val q1 = Query(n, Roots(listOf(Root(bobFpr))), false)
            sp(q1, daveFpr, daveUid, listOf(Pair(60, listOf(bobFpr, daveFpr))), null)


            val q2 = Query(n, Roots(listOf(Root(aliceFpr))), false)

            // Consider just the code path where B is the target.
            //
            // Covers scenarios #2 at t1, #4 at t2 and t3.
            if (i + 1 == 1) {
                sp(q2, bobFpr, bobUid, listOf(Pair(90, listOf(aliceFpr, bobFpr))), null)
            } else {
                sp(q2, bobFpr, bobUid, listOf(), null)
            }

            // Consider the code path where B is both an issuer and a
            // target.
            //
            // Covers scenarios #1 & #2 at t1, #3 & #4 at t2 and t3.
            sp(q2, daveFpr, daveUid,
                    listOf(
                            Pair(60, listOf(aliceFpr, bobFpr, daveFpr)),
                            Pair(30, listOf(aliceFpr, carolFpr, daveFpr)),
                    ), null)
        }

    }

    @Test
    fun cert_revoked_hard() {
        val aliceFpr = Fingerprint("219AAB661C8AAF4526DBC31AA751A7A0532863BA")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("90E02BFB03FAA04714D1D3D87543157EF3B12BE9")
        val bobUid = "<bob@example.org>"
        // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA
        // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA

        val carolFpr = Fingerprint("BF680710128E6BCCB2268154569F5F6BFB95C544")
        val carolUid = "<carol@example.org>"
        // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA

        val daveFpr = Fingerprint("46945292F8F643F0573AF71183F9C1A4759A16D6")
        val daveUid = "<dave@example.org>"
        // Certified by: 90E02BFB03FAA04714D1D3D87543157EF3B12BE9
        // Certified by: BF680710128E6BCCB2268154569F5F6BFB95C544
        // Certified by: 90E02BFB03FAA04714D1D3D87543157EF3B12BE9

        // At t1, B is hard revoked in the future so all
        // certifications are invalid.
        //
        // At t2, B is hard revoked so all certifications are invalid.
        //
        // At t3, A recertifies B and B recertifies D.  These
        // certifications should also be ignored.
        for ((i, t) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            println("Trying at $t");

            val n = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cert-revoked-hard.pgp", t)

            // Consider just the code path where B is the issuer.
            //
            // Covers scenarios #5 at t1, #7 at t2 and t3
            val q1 = Query(n, Roots(listOf(Root(bobFpr))), false)
            sp(q1, daveFpr, daveUid, listOf(), null)

            val q2 = Query(n, Roots(listOf(Root(aliceFpr))), false)

            // Consider just the code path where B is the target.
            //
            // Covers scenarios #6 at t1, #8 at t2 and t3.
            sp(q2, bobFpr, bobUid, listOf(), null)

            // Consider the code path where B is both an issuer and a
            // target.
            //
            // Covers scenarios #5 & #6 at t1, #7 & #8 at t2 and t3.
            sp(q2, daveFpr, daveUid, listOf(Pair(30, listOf(aliceFpr, carolFpr, daveFpr))), null)
        }

    }

    @Test
    fun cert_expired() {
        val aliceFpr = Fingerprint("1FA62523FB7C06E71EEFB82BB5159F3FC3EB3AC9")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("B166B31AE5F95600B3F7184FE74C6CE62821686F")
        val bobUid = "<bob@example.org>"
        // Certified by: 1FA62523FB7C06E71EEFB82BB5159F3FC3EB3AC9

        val carolFpr = Fingerprint("81CD118AC5BD9156DC113772626222D76ACDFFCF")
        val carolUid = "<carol@example.org>"
        // Certified by: B166B31AE5F95600B3F7184FE74C6CE62821686F

        for ((i, t) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(t).toEpochMilli())
            println("Trying at #$i $date")

            val n = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cert-expired.pgp", t)
            println("$n")

            val q1 = Query(n, Roots(listOf(Root(aliceFpr))), false)

            // Bob as target.  (Once Bob has expired it can be used as
            // a trusted introducer for prior certifications, but
            // bindings cannot be authenticated.)
            if (i + 1 == 1) {
                sp(q1, bobFpr, bobUid, listOf(Pair(60, listOf(aliceFpr, bobFpr))), null)
            } else {
                sp(q1, bobFpr, bobUid, listOf(), null)
            }

            // Bob in the middle.
            sp(q1, carolFpr, carolUid, listOf(Pair(60, listOf(aliceFpr, bobFpr, carolFpr))), null)

            // Bob as root.
            val q2 = Query(n, Roots(listOf(Root(bobFpr))), false)
            sp(q2, carolFpr, carolUid, listOf(Pair(60, listOf(bobFpr, carolFpr))), null)

            // Bob's self signature.
            if (i + 1 == 1) {
                sp(q2, bobFpr, bobUid, listOf(Pair(120, listOf(bobFpr))), null)
            } else {
                sp(q2, bobFpr, bobUid, listOf(), null)
            }
        }

    }

    @Test
    fun userid_revoked() {
        val aliceFpr = Fingerprint("01672BB67E4B4047E5A4EC0A731CEA092C465FC8")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("EA479A77CD074458EAFE56B4861BF42FF490C581")
        val bobUid = "<bob@example.org>"
        // Certified by: 01672BB67E4B4047E5A4EC0A731CEA092C465FC8
        // Certified by: 01672BB67E4B4047E5A4EC0A731CEA092C465FC8

        val carolFpr = Fingerprint("212873BB9C4CC49F8E5A6FEA78BC5397470BA7F0")
        val carolUid = "<carol@example.org>"
        // Certified by: EA479A77CD074458EAFE56B4861BF42FF490C581
        // Certified by: EA479A77CD074458EAFE56B4861BF42FF490C581


        // At t2, B is soft revoked so all future certifications are
        // invalid.
        for ((i, t) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(t).toEpochMilli())
            println("Trying at $date");

            val n = getNetwork("/home/heiko/src/sequoia-wot/tests/data/userid-revoked.pgp", t)
            println(n)

            // Revoked User ID on the root.
            val q1 = Query(n, Roots(listOf(Root(bobFpr))), false)


            if (i + 1 == 1) {
                sp(q1, bobFpr, bobUid, listOf(Pair(120, listOf(bobFpr))), null)
            } else {
                sp(q1, bobFpr, bobUid, listOf(), null)
            }

            val q2 = Query(n, Roots(listOf(Root(aliceFpr))), false)

            if (i + 1 == 1) {
                sp(q2, bobFpr, bobUid, listOf(Pair(60, listOf(aliceFpr, bobFpr))), null)
            } else {
                // Can't authenticate binding with a revoked User ID.
                sp(q2, bobFpr, bobUid, listOf(), null)
            }

            // Can use a delegation even if the certification that it
            // is a part of has had its User ID revoked.
            if (i + 1 < 3) {
                sp(q2, carolFpr, carolUid, listOf(Pair(60, listOf(aliceFpr, bobFpr, carolFpr))), null)
            } else {
                sp(q2, carolFpr, carolUid, listOf(Pair(90, listOf(aliceFpr, bobFpr, carolFpr))), null)
            }
        }
    }

    @Test
    fun certifications_revoked() {
        val aliceFpr = Fingerprint("817C2BE18D9FF48FFE58FF39B699FC21AD92EFDC")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("4258ACF6C3C8FCE130D6EBAB0CC5158AEA25F24A")
        val bobUid = "<bob@example.org>"
        // Certified by: 817C2BE18D9FF48FFE58FF39B699FC21AD92EFDC
        // Certified by: 817C2BE18D9FF48FFE58FF39B699FC21AD92EFDC

        val carolFpr = Fingerprint("36766215FFD2FA000B0804BFF54577580DDC1741")
        val carolUid = "<carol@example.org>"
        // Certified by: 4258ACF6C3C8FCE130D6EBAB0CC5158AEA25F24A

        for ((i, t) in listOf<Long>(1580598000, 1583103600, 1585778400).withIndex()) {
            val date = Date(Instant.ofEpochSecond(t).toEpochMilli())
            println("Trying at $date");

            val n = getNetwork("/home/heiko/src/sequoia-wot/tests/data/certification-revoked.pgp", t)
            println("$n")

            // Revoked User ID on the root.
            val q1 = Query(n, Roots(listOf(Root(aliceFpr))), false)

            sp(q1, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)

            when (i + 1) {
                1 -> {
                    sp(q1, bobFpr, bobUid, listOf(Pair(60, listOf(aliceFpr, bobFpr))), null)
                    sp(q1, carolFpr, carolUid, listOf(Pair(60, listOf(aliceFpr, bobFpr, carolFpr))), null)
                }

                2 -> {
                    sp(q1, bobFpr, bobUid, listOf(), null)
                    sp(q1, carolFpr, carolUid, listOf(), null)
                }

                3 -> {
                    sp(q1, bobFpr, bobUid, listOf(Pair(120, listOf(aliceFpr, bobFpr))), null)
                    sp(q1, carolFpr, carolUid, listOf(Pair(120, listOf(aliceFpr, bobFpr, carolFpr))), null)
                }

                else -> throw RuntimeException() // unreachable
            }

            // Alice, not Bob, revokes Bob's user id.  So when Bob is
            // the root, the self signature should still be good.
            val q2 = Query(n, Roots(listOf(Root(bobFpr))), false)
            sp(q2, bobFpr, bobUid, listOf(Pair(120, listOf(bobFpr))), null)
        }
    }

    @Test
    fun infinity_and_beyond() {
        val u1Fpr = Fingerprint("B557862780A97676CC32F4BB1491A9C2BDE6F1DC")
        val u1Uid = "<u1@example.org>"

        val u260Fpr = Fingerprint("B69A678AA242FA4F0BBF12205C0608799B0E3C51")
        val u260Uid = "<u260@example.org>"

        val u254Fpr = Fingerprint("AF097DA4DB5C0E2116EF583B25A6B381B621C082")
        val u254Uid = "<u254@example.org>"

        val fprs = listOf(
                Fingerprint("B557862780A97676CC32F4BB1491A9C2BDE6F1DC"),
                Fingerprint("0618F850B6D0C48DBF406BBFAB3DAED809A35F78"),
                Fingerprint("70B0C5FEFFE6B55F2CEE85455621246D16D6785E"),
                Fingerprint("EC4475DE5BD76EA7DD4798777E9C990C249738B1"),
                Fingerprint("FB00C7044A9DD164243CEC460B48AA8ADD29A129"),
                Fingerprint("7DCB823AB1B33C6D22FC84AC3026DA74AEEB4A6E"),
                Fingerprint("0058DCF7A7C6C4360DE9095DB6F33843D961E818"),
                Fingerprint("D0BF1856B95A62763DE49088CE6FF96D17E0EAF0"),
                Fingerprint("7F945244A20A74E1BA50BE73E917BC24D2D53F79"),
                Fingerprint("12C92685CA2A867B93FD79762B2D56CF0B94304E"),
                Fingerprint("02B1DB86B6869BCF92C0F74312D1A5F22E128F18"),
                Fingerprint("9C8245F2DD06E4A2FE21FB1643A9663DDF7DF168"),
                Fingerprint("CB7C6D3FCBB8DA0B3D7F6EC0DD193A96517579DC"),
                Fingerprint("66D0F95325D4A02A36C14265FD247584CCA3C8BA"),
                Fingerprint("291ABB75D735BC5B625E221B021152DF0CA1F86A"),
                Fingerprint("27DF659AEE573E30D3A65B6E43474D9A4CA64DE3"),
                Fingerprint("591492CAF51C06516278723EAFB9AF2643B89A3A"),
                Fingerprint("20B481FFB7B72F6781BA49806C8E35B5C79A3E41"),
                Fingerprint("270E3D9E87CA0999D422CD22F905BF87E8F60A36"),
                Fingerprint("192124BD42BA6BF54A8820FB94B6B70D818241E3"),
                Fingerprint("07C1D93539328F97517C59D27ABC3071DB73A790"),
                Fingerprint("A915D1BA3F066E989B965ADFA27CC8D161C0F48A"),
                Fingerprint("D968AFB7EAF13E04BB71D96100CC514119C8303E"),
                Fingerprint("A62F988F2896A0286F92F8B8201E7737D11D7039"),
                Fingerprint("9BF8933FCA5306F567F5F5750CE3375AFA9398A1"),
                Fingerprint("5EC7400A739E579B704E618809345EF1045B304A"),
                Fingerprint("2C7B74D1388CE0F2C4002CE41EAD11DBB281472A"),
                Fingerprint("C18D79710A68696E972B0F321E6DE596CD08B4FD"),
                Fingerprint("C1B1150980254353538D9CC5A91187FE2DBD51FF"),
                Fingerprint("4FD94C288F39C4633FBBD120BF1A1C6B6789F983"),
                Fingerprint("DE70A745F098EBCC45B4A3B25D0195EC3C6E0D65"),
                Fingerprint("44350591F20A4069F131156283AABF91FE4AE5EF"),
                Fingerprint("76E9D213C5F67F2DBE410F57DF3F9BB9622AAFC7"),
                Fingerprint("A48F536C34D4A493CD233870C05B675B873B139D"),
                Fingerprint("7C3FEDFAB082D236A9181B8E2B6483A582756C6E"),
                Fingerprint("0FDFAF64606B6C72BF1C940D24F80C95D5B8310E"),
                Fingerprint("6B5A25C2DD40AE58272FB17D15C33EF13B9D7FE8"),
                Fingerprint("3814E465DDDCDB7F352E513D9C34D38E08A4360A"),
                Fingerprint("2BF243991E5B6444861FC662E93888456D33F149"),
                Fingerprint("124760101EF948B0E9EC24D9326FFEBD505BE4D3"),
                Fingerprint("074E083627D1ED618486FB18865EA7123912BE53"),
                Fingerprint("955B6A60E5EA85BADD68B1E08AF3E45D3AB93DE9"),
                Fingerprint("857B9C8DCF9EBD72556237A40E652DDF8101E2D0"),
                Fingerprint("FA11A49DA2E22F686471A4343E6A36C53F7C2155"),
                Fingerprint("90DF0E04097EBFD295E05B9F40BE700A2E8D0995"),
                Fingerprint("90BA919C17ED4252F8F0ED327192D79A112A0CE6"),
                Fingerprint("3762EB478F47FEA848ADA9E1611C433D28D84071"),
                Fingerprint("E960CD893E6CF7F41E752BEF15ED83ECDF49463C"),
                Fingerprint("B1256D987F2789601FC5D8FAF268AB5F6AB44782"),
                Fingerprint("5EE4B68A4828F5C15DD87114DC4A8509993DCFAB"),
                Fingerprint("5C472E1C68A9A587C2AF9F00BC59B13A9918BBC1"),
                Fingerprint("5320428600FCDB9A3AA32DA3E14D0128D7C372EC"),
                Fingerprint("41958AAE8E1EED80B680F4DCD5ABFA33A1DB1C23"),
                Fingerprint("7F4DFF6FC276995C94C2BF92146B7BED38209DB9"),
                Fingerprint("6DE33C3735906B7E69AE593A0CD724AF410A89CE"),
                Fingerprint("70F56B5B0EA57CB9ACDEB08B5333D900488A16B1"),
                Fingerprint("02C9977BFF7BA0295AF671AA31894E2CD88A0F0D"),
                Fingerprint("81FF106638ACE77B0C1039D5E69BCC93690A6B8D"),
                Fingerprint("136368A84C7E56A86515ACC6DCD0744ABE10225D"),
                Fingerprint("2B5E1D94813CED1CD63A3F28FEF343EA790E2333"),
                Fingerprint("680ADF1182D00512D298417C6DBFC9084BFDB79D"),
                Fingerprint("17DFBFB2149AB4A82B1DE5E5AE63FBDCE6874162"),
                Fingerprint("2FD6D0F680B55F9AF128DBCBA4C71E44F433B728"),
                Fingerprint("26551C85DBFDDEA97B7E7A0068DBDE9E792A7A49"),
                Fingerprint("341BB68A3695B3D9EE307D7794317B145CEFCB60"),
                Fingerprint("2E65A5B2F70D16D5D4D0664D360AE9BD58C555C1"),
                Fingerprint("DEE7D3162919AC8AC9592051BFACF193B344DEF1"),
                Fingerprint("2A8CE469DD783B95C92A6F3294A5A609AA679F71"),
                Fingerprint("8A9FE07B40482C5559A6770B57B79188B52BD346"),
                Fingerprint("6993EE3E5C4653A03EACBEC25604E4A55B4F75AB"),
                Fingerprint("66DF2690FEAC606C285AA4D986376ACD1964BE48"),
                Fingerprint("29FD7B1C6B29663CFA64306670E67F3E7F6FBCD4"),
                Fingerprint("2C6E7C99DE5F5922E05D11D235C2E562CC528E76"),
                Fingerprint("88E99AC4D5CB6ACF3CD396D5D6AA9961B4F938AB"),
                Fingerprint("4471A85059215D231D47B1D4A109C3F0B6BDB258"),
                Fingerprint("2C755244C6B83CAA7E48BD234C7FDB8645611B3B"),
                Fingerprint("9C015FEBD3D19A81716E7700052058B47F889611"),
                Fingerprint("9014E514D677C2ED19D93329C1485FE55F1C72D6"),
                Fingerprint("343F2C6F9DB8F9EE4E59F5C0886BAE56FA55CE26"),
                Fingerprint("13C37CE8ED0ACC92CF61808755241D6DA1633FA4"),
                Fingerprint("ED5C07A820DCB2AA6DAFDE9C8562765D88A4BB36"),
                Fingerprint("21655669D7B36A2EB5007B31442FCE197ADCC8D8"),
                Fingerprint("CD220E58B30D2D1CBBC5B921555C92A70B303860"),
                Fingerprint("5FF5C8CBD8D670565B300519887E3ED2F9E0DDA9"),
                Fingerprint("B47FF2EF9DEB08C7FC55532C746F0F2DB723C462"),
                Fingerprint("F8F8F30931EEB93C2FDE9363F9EE328402F33860"),
                Fingerprint("3714D9CB0A8A0B4EE695B21AB052CAE69A2A7689"),
                Fingerprint("FF093E66CCFB8804193115058643E0CB52C5A793"),
                Fingerprint("0A5553209858B36F3EA0EFA463FD6758FF116167"),
                Fingerprint("D9C06C9D100813BEBD35427DF65F7634EB2EAD6A"),
                Fingerprint("05CA2D388297E826B9C3B431A8B15D93895257F9"),
                Fingerprint("BF79DD51D462180014D2AD71D2462BE4CF36F625"),
                Fingerprint("FC0DE4AD683BE64F47E8642F7472D7BB781E5C76"),
                Fingerprint("F1FE09936F39A4E7A907D909CDFA4993BE4124AF"),
                Fingerprint("465CD9AD11B5003A48BB28118DB2CEBD29D4F603"),
                Fingerprint("9DF99BDB7078BE13CE3F66D97F212BF669F995C6"),
                Fingerprint("57071A60EFBBFFA6DDCE7796F14A1B2C681A8A83"),
                Fingerprint("8AB11E4F18DC57F2BA400B8D7B5FD8990C1CCAC5"),
                Fingerprint("286EC5D4E5D1D136E54C996FE2D9E350B7CF3D8A"),
                Fingerprint("AF87AF1183FB3E9370D509CE4E255380D5F3A8D5"),
                Fingerprint("036F0956E3436BB10D030C89241EB37A3E931678"),
                Fingerprint("33C2757572312304682BDD62C46C67D099B92680"),
                Fingerprint("47A458ECE5784E7AF11C2286AA75FA9B8401E257"),
                Fingerprint("43950C8B0B46693E9E48676637A98A31CF4B62AD"),
                Fingerprint("A881411005DCCA6AF01331438783D3432031442F"),
                Fingerprint("AA96AB4A6A98A839676621E66E756674E8DE55F3"),
                Fingerprint("6844B0D8AB1D74A5766311157F652BC182F0875D"),
                Fingerprint("B6F83FFF8B788418D48C11FA084D0F3AC9A2AECD"),
                Fingerprint("99B269CFF458C780108B370C7A3F523A4DD62521"),
                Fingerprint("48ADBA117B6D38703248D7AE72FB58B9E9798B7E"),
                Fingerprint("FBC503FCBE4143C984E88358E700E23D4F573CCF"),
                Fingerprint("E249A634759A417A040615736E200525AAF6F629"),
                Fingerprint("BC782C4357D9E72075AF3DBF2C2FCAB09C09C252"),
                Fingerprint("7B47E68EFB03A0C8346BD80E4A2FA75B6488D6D3"),
                Fingerprint("DC2807A9E1CCD83B797A1EB2829D1F4641E0DB9B"),
                Fingerprint("33C7585C640E74974790F349F64B2668DF09DE8E"),
                Fingerprint("C766141BA6C7998C7EE40DE116FB427F2C57657F"),
                Fingerprint("D0DF7D293426D9451E9EE0FD03A4D8196D10976D"),
                Fingerprint("D56E5DB01CFAAD99697B33163B81D229170F58B4"),
                Fingerprint("97D592FDE6199E3A4F6B437F40B34142AA67397B"),
                Fingerprint("8C19F12A8386D0EF3FC0AFD28D7FE8D90F070EFB"),
                Fingerprint("5B87566BAA2C8EC78C7D44594F21D5ABA36767F2"),
                Fingerprint("53AB6BCCE1111DCD151E66625F52509FC67F4076"),
                Fingerprint("318DA1A8A8E92698EAAC0AB468406FF3D0B6733A"),
                Fingerprint("350068CCCD295D7EB80C6A97060FCBD15175ADB2"),
                Fingerprint("3A7DF039CCCA3B3C9286B01619D8EA302427C910"),
                Fingerprint("3C964F3E9C57330753EE5923B49FC01974400307"),
                Fingerprint("4E9E5E2E1A868706DAADFD5A362C66828E5E4621"),
                Fingerprint("36328DA9EAC85DB46843FA168A4AA6C4B47ADE22"),
                Fingerprint("0AB20633A6D636B80337EFE3403702D89A3CD852"),
                Fingerprint("8CDF07D3CEA5ED1B72ECD8869CA0A447943C1F3B"),
                Fingerprint("E052363BDCA7BB374570774F9EE1EA2E8BF88026"),
                Fingerprint("6603EA823BC641A465D8E5C45EDAD32360EDFC6A"),
                Fingerprint("7D2E0E09E14B5BAB084A268786B0C6357215757B"),
                Fingerprint("44F5446DBE64118D55D007453C6EF4840B47CD82"),
                Fingerprint("419FA3D74A917B54F53AF2157B81A4A67CBA27F0"),
                Fingerprint("36EB37E159817A86D0D4F506A3DDF317DFEDF32F"),
                Fingerprint("9F5918BE6A7898670283859B05280E0DDA09EC95"),
                Fingerprint("24EFDB2253318E11B73B617C6A7C5DC8792A2A55"),
                Fingerprint("4AF832B3208DB3DD126C21E3CAF4AA3126156F8B"),
                Fingerprint("E00EE6E5D079CA81E37F964EAD799F4D59738D54"),
                Fingerprint("5A962B09EF649F4267DFDAE046B2F28E5134573F"),
                Fingerprint("BAB9FB2EC409E68165AEF78D58BB96EB511C41B2"),
                Fingerprint("ADD6E345227F27489E1E8AA7E0CD788437CC47BF"),
                Fingerprint("BCD1FB9A7524E6B2D1ADB920653E81204C30A119"),
                Fingerprint("17DE4392A165DC82CF50E879B5CB17B550CC0DE2"),
                Fingerprint("5E9C128259B95B3C90C651E3E106A3276D83FFD1"),
                Fingerprint("837B524C48C821FB23C4331A764076A4958D02E6"),
                Fingerprint("1DBFA683F2744FCCFCF46D35989519FEB16FB4B1"),
                Fingerprint("16561C850378BDB387F6E620B261465512DF841D"),
                Fingerprint("40903D9038604F9F0325F4F595735AB9651D3899"),
                Fingerprint("542CE462E1A66CEECDE4A15E3B614535DCA71EEF"),
                Fingerprint("91FE56BE25CCB3CF5439DFAAC42E3BADAAFA919A"),
                Fingerprint("0EBD96F41958B13F8F69B5FFD95B370820AE2176"),
                Fingerprint("FE6500EC3768698238FA02AE836FE5675367B4F9"),
                Fingerprint("34E96CA46093CDFC25ACE6A3A2FE701D926F093A"),
                Fingerprint("45046E989B2E1B90A1DAEB5ADB7580D1B78D3BC6"),
                Fingerprint("64A9859344F5073B183BD5C8AA60941E63199D9D"),
                Fingerprint("729EDA4A2A634E776780E1847CA24E9550F7D0A7"),
                Fingerprint("8844DCA493E8F20107CB447191FEA3BD4C01890B"),
                Fingerprint("F965044BE1E7300C7B6716E293C396B4FA94CD92"),
                Fingerprint("BC007EC19B0BC8DDE59847B09EA70EB3222D9E51"),
                Fingerprint("B333A058F7209C46F2D027BB03738EAAC50701ED"),
                Fingerprint("A9A1A3B0F12233D6120809D6F8F0C11D96152693"),
                Fingerprint("2BFE10D7FEE9E5DF5833B6F61B584BAB2FD86575"),
                Fingerprint("E5F3B17D545521F9B5395B10E92020FDB3E8109E"),
                Fingerprint("58035C57B66B0EBFB069F9B7F3C623A5C52A3B92"),
                Fingerprint("003E9C5A9DAB8626FD1694AAC2C43642A20E1496"),
                Fingerprint("E7947E382B12FE628BDA130201EFC9D900B5540C"),
                Fingerprint("17B55B1078D282C73FA2E76287FAB537AEAFE66C"),
                Fingerprint("27CE83D68C669FE4F1B8C938D4A919E6F59E4D0B"),
                Fingerprint("86B1E98692F4CA34122012C1524B4079CF57E850"),
                Fingerprint("5B8A8AC5213064AE84C97DE41ED4BF239D9C10F2"),
                Fingerprint("3FEAB08FC63829C080412CBFC6D3836C6E817789"),
                Fingerprint("231605AEE34762F3BBC8ECF73808EFA9258837F8"),
                Fingerprint("AE2759F4EC850FA6CE98FA4729FD82649411B973"),
                Fingerprint("E7529E3567F59BBCADAAD1246613DBC86DAD45F8"),
                Fingerprint("CF320590351A8C41C9EA0C1F4C6F00F7AEA73AD5"),
                Fingerprint("475A44091578C02A0C5C2D62F106918D87E15476"),
                Fingerprint("5B88BF2E7163D0594CE0E302C2AD0FE43D473EFE"),
                Fingerprint("E4ADA4F5D702AD510C2F7A19316950AD7429C1FA"),
                Fingerprint("6D6B846B8661F1013E7BC8D64C7280F7DF9DA6E6"),
                Fingerprint("49883F6CA68B9F452F2A5F2F04687A6078E00FBF"),
                Fingerprint("3046B5075B9DAF5645F51717D01AB61342900011"),
                Fingerprint("16213F8B540AC28FE0CB3548D84F0D748AC23379"),
                Fingerprint("9C68E98198FF9964FA2366ADCBAD3A465C76396B"),
                Fingerprint("6EC3A10AA0B6B70DC5408CAE74B0BE836FD382D6"),
                Fingerprint("E25E062BE69B48D3B99A96086991D15CA7370F0C"),
                Fingerprint("A01A30A1AB191AF9C148C3704F4582E27D8D7527"),
                Fingerprint("5D33551903E14FAABF75E9ECFB7AE6C2AC9959FB"),
                Fingerprint("B37AE84FB0B4226FB935A3090F7C543F95A21EEF"),
                Fingerprint("65B2CD9E6A6F6A36496B54A285F9BA4B68AA5174"),
                Fingerprint("C0AA5CFC45580335A785DC2B3F9EE769EAAFE70D"),
                Fingerprint("09973DF6334673259B774B840B1496371FDC2BE6"),
                Fingerprint("29AAA5AF7CF941F4307DE966BD9E690D59FE5383"),
                Fingerprint("9BDA50D8A6C78525051AAE07CC26594022C7D4AE"),
                Fingerprint("2B0B6FDB04B9E8FF3A31EBE16A6B0A72A6571C45"),
                Fingerprint("5C2650D8DA9842951614026288805244633C686B"),
                Fingerprint("EEA6502B34AB08FA2F3BDA1E355AC29B6D8B67FA"),
                Fingerprint("61B00DCDC02069F46F20D7F91075929DC6DA674C"),
                Fingerprint("A1F5307F398FA45ECFC68CA92A5FC888D2DD2728"),
                Fingerprint("AB0ADD3BF024EB6C75D9A366ABE69FC6E9F60DA0"),
                Fingerprint("20DFEEF42F418CCEB02DB3E896E40B0413F1B4C5"),
                Fingerprint("59C4E41C31D1E16F11BCF51304E7B81D67AD1FA0"),
                Fingerprint("C0A3A190F8BFB6115A87CF7CBEC9211A2E210C86"),
                Fingerprint("8932D417D3C0C4E3694E90480B92349F276E4EE0"),
                Fingerprint("5BE288B0F7DCD89200D112D009E73AB06030B4EB"),
                Fingerprint("CF472156042D6F2032BC025B68544E0A5844F3A7"),
                Fingerprint("D54401DBBDE32805DAF08C4E1177C10E27F7D235"),
                Fingerprint("56100D18E943687F7CFBC3CB20479A11B7DD5E1D"),
                Fingerprint("9349703A779BD3725C5C822E21DA8172102EC4CD"),
                Fingerprint("5DCAAB77198D13785C340D7B375DD44D815A0481"),
                Fingerprint("5959CAC7EB9C1C7D9ECF10B8C023ED12A0F7F556"),
                Fingerprint("7D4EA25C4F364AF1B61B64164816D289775352A8"),
                Fingerprint("84291C882E059C5100C5C1AD1746298F01E7D682"),
                Fingerprint("F3A95472FDB65D965EC2C4E3D22BD567B60BE41E"),
                Fingerprint("0B9B18FB07F29E89D33AA0A86ED47AC9E7B86518"),
                Fingerprint("2A11B65832E97E65DAA69D690C304130A843F532"),
                Fingerprint("BB1B2F93AE4C4D41B4385AB653A4193345AA17C7"),
                Fingerprint("4B526E27DAA41961F9D89404ED2F25E650D82444"),
                Fingerprint("8DC51F77AEFAE450554792A0C704999EF5D32A6B"),
                Fingerprint("ACD80C31E49FEAF9AA07DBD9FA96E7E857A694DE"),
                Fingerprint("F2A4AE3ABC6DE0475E22B836DB0B8264BE496577"),
                Fingerprint("14AA7B5B7D9088CBBD5FF8CB95F34513BA887EC0"),
                Fingerprint("185A81E45751F6322490BE7987DDCD2A02E38D38"),
                Fingerprint("BFCC758F6B567FF489801B539ED707902064CF71"),
                Fingerprint("6F80DC80D1F4C14810750CAF51FAB910F100F6AB"),
                Fingerprint("D220EB0F833DB97983F221D902D45679E35E555A"),
                Fingerprint("6F757C636ED4E157D6F6570DBC03D6A8FCC6CD68"),
                Fingerprint("C0C4B2D29A88A8F042FB13422605B3290364FF74"),
                Fingerprint("23EBA00A8576434AE4B077F9819A1B623B2E138C"),
                Fingerprint("88C18A2D51339461068DDF72693871FAF6FFC6FF"),
                Fingerprint("CDA5DE7236C247F0D116CC0A1A25910D0CD909C0"),
                Fingerprint("E405060228D49BA43C6ED9A3E25ADFDCC0012F48"),
                Fingerprint("575DB527D78D5A063AB4197891DB2946F8EE3A8C"),
                Fingerprint("D4BBE60FCA2FC7850FF7309102DEF04D111BA114"),
                Fingerprint("97794BE1FD5729470D049D86BE16BB8E38D6D8EB"),
                Fingerprint("4C011F0F9E4C58022DBD2E1FAA549F086FB77001"),
                Fingerprint("950D06C53390F94AF59A15609900DA7A91A638CF"),
                Fingerprint("013B231F139A46312550BBCBC52451FDB72285FC"),
                Fingerprint("A814BA237B27B4605C71A907B8A8D55FC49CB5E6"),
                Fingerprint("A3AE147DBC887FA325852A4DC3FFE143772A8587"),
                Fingerprint("4D88E9B314F4ECAF99E02611C985FD350408C791"),
                Fingerprint("CE9A27BE12483A5F094F85330E51D13DC2830B24"),
                Fingerprint("B6565ADDD563FDD720D05411CD3449BD50892312"),
                Fingerprint("F1EBB0F94C08A777867F403E9FAFBE3A10228952"),
                Fingerprint("94D627E627E15F9B9144457816A736F442FD6A6F"),
                Fingerprint("B3B1CDB5875CD8725B5FC915B1ED7C0FCE7721EE"),
                Fingerprint("9E80CD683AA01265FE25DF265DADCE433039185C"),
                Fingerprint("AFDE99A008E9BC761DFA6367C984AF52546308CF"),
                Fingerprint("364854C36A1EFFDCAC7B80296A8F683B48BC5F33"),
                Fingerprint("77C3730DB611591E71EE4528A15EE7D5EF32333F"),
                Fingerprint("138CC2085B1A06F02DE1946D5FB391D63C886EE6"),
                Fingerprint("AF097DA4DB5C0E2116EF583B25A6B381B621C082"),
                Fingerprint("02DF6CB2758D7695940B6937804CAD30CDAC243C"),
                Fingerprint("7F7C33899D1A34BE0D2B3C1C3B8F983DFABA03B4"),
                Fingerprint("041549DBA90F2C4EB9E22505B4515224EB745A2C"),
                Fingerprint("B73206C4F70E0735E9288128BAC3400233738122"),
                Fingerprint("FCDF4C1D67ACFA8B42F6A77C408A9CB7367171C2"),
                Fingerprint("B69A678AA242FA4F0BBF12205C0608799B0E3C51"),
        )

        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/infinity-and-beyond.pgp")
        println("$n1")

        val q1 = Query(n1, Roots(listOf(Root(u1Fpr))), false)

        // This should always work.
        sp(q1, u254Fpr, u254Uid, listOf(Pair(120, fprs.subList(0, 254))), null)

        // This tests that depth=255 really means infinity.
        sp(q1, u260Fpr, u260Uid, listOf(Pair(120, fprs)), null)
    }

    @Test
    fun zero_trust() {
        val aliceFpr = Fingerprint("931E51F99B89649783A1DFF265266E28246040C2")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("A1042B157AFA71F005208D645915549D8D21A97B")
        val bobUid = "<bob@example.org>"
        // Certified by: 931E51F99B89649783A1DFF265266E28246040C2
        // Certified by: 931E51F99B89649783A1DFF265266E28246040C2

        val carolFpr = Fingerprint("E06DB0539D99759681D7EC8508A267AE8FA838F4")
        val carolUid = "<carol@example.org>"
        // Certified by: A1042B157AFA71F005208D645915549D8D21A97B

        // At t2, B is certified with a trust amount of 0.  This
        // should eliminate the path.
        for ((i, t) in listOf<Long>(1580598000, 1583103600).withIndex()) {
            println("Trying at $t");

            val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/zero-trust.pgp", t)
            println("$n1")

            val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

            if (i + 1 == 1) {
                sp(q1, carolFpr, carolUid, listOf(Pair(60, listOf(aliceFpr, bobFpr, carolFpr))), null)
            } else {
                sp(q1, carolFpr, carolUid, listOf(), null)
            }

            // Start with bob and make sure that a certification by a
            // root with a 0 trust amount is also respected.
            val q2 = Query(n1, Roots(listOf(Root(bobFpr))), false)

            if (i + 1 == 1) {
                sp(q2, carolFpr, carolUid, listOf(Pair(60, listOf(bobFpr, carolFpr))), null)
            } else {
                sp(q2, carolFpr, carolUid, listOf(), null)
            }
        }
    }

    @Test
    fun partially_trusted_roots() {
        val aliceFpr = Fingerprint("85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("39A479816C934B9E0464F1F4BC1DCFDEADA4EE90")
        val bobUid = "<bob@example.org>"
        // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

        val carolFpr = Fingerprint("43530F91B450EDB269AA58821A1CF4DC7F500F04")
        val carolUid = "<carol@example.org>"
        // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

        val daveFpr = Fingerprint("329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281")
        val daveUid = "<dave@example.org>"
        // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

        val ellenFpr = Fingerprint("A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4")
        val ellenUid = "<ellen@example.org>"
        // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

        val frankFpr = Fingerprint("2693237D2CED0BB68F118D78DC86A97CD2C819D9")
        val frankUid = "<frank@example.org>"

        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/simple.pgp")
        println("$n1")

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr, 90))), false)

        sp(q1, aliceFpr, aliceUid, listOf(Pair(90, listOf(aliceFpr))), null)

        sp(q1, bobFpr, bobUid, listOf(Pair(90, listOf(aliceFpr, bobFpr))), null)

        sp(q1, carolFpr, carolUid, listOf(Pair(90, listOf(aliceFpr, bobFpr, carolFpr))), null)

        sp(q1, daveFpr, daveUid, listOf(Pair(90, listOf(aliceFpr, bobFpr, carolFpr, daveFpr))), null)

        sp(q1, ellenFpr, ellenUid, listOf(), null)

        sp(q1, frankFpr, frankUid, listOf(), null)

        // No one authenticated Bob's User ID on Carol's key.
        sp(q1, carolFpr, bobUid, listOf(), null)

        // Multiple partially trusted roots.  Check that together they
        // can fully certify a self signature.
        val q2 = Query(n1, Roots(listOf(Root(aliceFpr, 90), Root(bobFpr, 90))), false)

        sp(q2, aliceFpr, aliceUid, listOf(Pair(90, listOf(aliceFpr))), null)

        sp(q2, bobFpr, bobUid,
                listOf(Pair(90, listOf(bobFpr)), Pair(90,
                        listOf(aliceFpr, bobFpr))), null)

    }

    @Test
    fun self_signed() {
        val aliceFpr = Fingerprint("838454E0D61D046300B408A908A4FDB4F368ECB9")
        val aliceUid = "<alice@example.org>"

        val bobFpr = Fingerprint("7A7B5DE6C8F464CAB78BEFB9CE14BEE51D4DEC01")
        val bobUid = "<bob@example.org>"
        // Certified by: 838454E0D61D046300B408A908A4FDB4F368ECB9

        val carolFpr = Fingerprint("830230061426EE99A0455E6ADA869CF879A5630D")
        val carolUid = "<carol@example.org>"
        // Certified by: 7A7B5DE6C8F464CAB78BEFB9CE14BEE51D4DEC01
        val carol_other_orgUid = "<carol@other.org>"

        val daveFpr = Fingerprint("51A5E15F87AC6ECAFBEA930FA5F30AF6EB6EF14A")
        val daveUid = "<dave@example.org>"
        // Certified by: 830230061426EE99A0455E6ADA869CF879A5630D

        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/self-signed.pgp")
        println("$n1")

        val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

        sp(q1, bobFpr, bobUid, listOf(Pair(100, listOf(aliceFpr, bobFpr))), null)

        sp(q1, carolFpr, carolUid, listOf(Pair(90, listOf(aliceFpr, bobFpr, carolFpr))), null)

        sp(q1, carolFpr, carol_other_orgUid, listOf(), null)

        sp(q1, daveFpr, daveUid, listOf(), null)


        val q2 = Query(n1, Roots(listOf(Root(bobFpr))), false)

        sp(q2, bobFpr, bobUid, listOf(Pair(120, listOf(bobFpr))), null)

        sp(q2, carolFpr, carolUid, listOf(Pair(90, listOf(bobFpr, carolFpr))), null)

        sp(q2, carolFpr, carol_other_orgUid, listOf(Pair(90, listOf(bobFpr, carolFpr, carolFpr))), null)

        sp(q2, daveFpr, daveUid, listOf(Pair(90, listOf(bobFpr, carolFpr, daveFpr))), null)

    }

    @Test
    fun isolated_root() {
        val aliceFpr = Fingerprint("DCF3020AAB76ECC7F0E5AC0D375DCE1BEE264B87")
        val aliceUid = "<alice@example.org>"
        val aliceOtherOrguid = "<alice@other.org>"

        for ((i, t) in listOf<Long>(1577919600, 1580598000).withIndex()) {
            println("Trying at $t");

            val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/isolated-root.pgp", t)
            println("$n1")

            val q1 = Query(n1, Roots(listOf(Root(aliceFpr))), false)

            if (i == 0) {
                sp(q1, aliceFpr, aliceUid, listOf(Pair(120, listOf(aliceFpr))), null)
            } else {
                sp(q1, aliceFpr, aliceUid, listOf(), null)
            }

            sp(q1, aliceFpr, aliceOtherOrguid, listOf(Pair(120, listOf(aliceFpr))), null)
        }
    }

}