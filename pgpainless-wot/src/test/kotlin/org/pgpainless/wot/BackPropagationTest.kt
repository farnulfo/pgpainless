package org.pgpainless.wot

import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.wot.dijkstra.Query
import org.pgpainless.wot.network.Roots
import org.pgpainless.wot.dijkstra.filter.IdempotentCertificationFilter
import org.pgpainless.wot.network.Fingerprint
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.Root
import org.pgpainless.wot.query.Path
import java.io.File

private const val DEPTH_UNCONSTRAINED = 255

/**
 * Unit tests, ported from https://gitlab.com/sequoia-pgp/sequoia-wot/-/blob/main/src/backward_propagation.rs
 */
class BackPropagationTest {

    // Compares a computed path and a trust amount with the expected result.
    private fun checkResult(result: Pair<Path, Int>,
                            residualDepth: Int,
                            amount: Int,
                            expectedPath: List<Fingerprint>) {

        val (gotPath, gotAmount) = result;
        val gotCerts: List<Fingerprint> = gotPath.certificates.map { it.fingerprint }

        assert(gotCerts.size == expectedPath.size)
        assert(gotCerts.zip(expectedPath).none { it.first != it.second }) // FIXME: debug output?

        assert(gotAmount == amount) { "Amount mismatch, got $gotAmount, expected $amount" }
        assert(gotPath.residualDepth.value() == residualDepth
        ) { "Residual depth mismatch, got " + gotPath.residualDepth.value() + ", expected " + residualDepth }

        // NOTE: the Rust tests also check for validity of the path,
        // but we're separating those concerns here.
        // This package only deals with WoT calculations.
    }

    private fun getNetwork(filename: String): Network {
        val inputStream = File(filename).inputStream()
        val keyrings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream)

        val store = KeyRingCertificateStore(keyrings)

        return WebOfTrust(store).buildNetwork()
    }

    @Test
    fun simple() {
        val network = getNetwork("/home/heiko/src/sequoia-wot/tests/data/simple.pgp")
        println("Network contains " + network.nodes.size + " nodes with " + network.numberOfEdges + " edges built from " + network.numberOfSignatures + " signatures.")

        // --

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

        val q = Query(network, Roots(), false)


        val a1 = q.backwardPropagate(ellenFpr, ellenUid, false, IdempotentCertificationFilter())

        checkResult(a1[daveFpr]!!, 1, 100, listOf(daveFpr, ellenFpr));
        checkResult(a1[carolFpr]!!, 0, 100, listOf(carolFpr, daveFpr, ellenFpr));


        val a2 = q.backwardPropagate(daveFpr, daveUid, false, IdempotentCertificationFilter());

        assert(a2[ellenFpr] == null);
        checkResult(a2[carolFpr]!!, 1, 100, listOf(carolFpr, daveFpr));
        checkResult(a2[bobFpr]!!, 0, 100, listOf(bobFpr, carolFpr, daveFpr));
        checkResult(a2[aliceFpr]!!, 0, 100, listOf(aliceFpr, bobFpr, carolFpr, daveFpr));


        val a3 = q.backwardPropagate(daveFpr, daveUid, false, IdempotentCertificationFilter());

        assert(a3[ellenFpr] == null);
        checkResult(a3[carolFpr]!!, 1, 100, listOf(carolFpr, daveFpr));
        checkResult(a3[bobFpr]!!, 0, 100, listOf(bobFpr, carolFpr, daveFpr));

        // This should work even though Bob is the root and the path is via Bob.
        checkResult(a3[aliceFpr]!!, 0, 100, listOf(aliceFpr, bobFpr, carolFpr, daveFpr));

        val a4 = q.backwardPropagate(daveFpr, daveUid, false, IdempotentCertificationFilter());

        assert(a4[ellenFpr] == null)
        checkResult(a4[carolFpr]!!, 1, 100, listOf(carolFpr, daveFpr));

        // This should work even though Carol is the root is the path is via Carol.
        checkResult(a4[bobFpr]!!, 0, 100, listOf(bobFpr, carolFpr, daveFpr));
        checkResult(a4[aliceFpr]!!, 0, 100, listOf(aliceFpr, bobFpr, carolFpr, daveFpr));

        // Try to authenticate dave's key for an User ID that no one has certified.
        val a5 = q.backwardPropagate(daveFpr, ellenUid, false, IdempotentCertificationFilter());

        assert(a5[ellenFpr] == null);
        assert(a5[daveFpr] == null);
        assert(a5[carolFpr] == null);
        assert(a5[bobFpr] == null);
        assert(a5[aliceFpr] == null);

        // A target that is not in the network.
        val fpr = Fingerprint("0123456789ABCDEF0123456789ABCDEF01234567")
        val a6 = q.backwardPropagate(fpr, ellenUid, false, IdempotentCertificationFilter());

        assert(a6[ellenFpr] == null);
        assert(a6[daveFpr] == null);
        assert(a6[carolFpr] == null);
        assert(a6[bobFpr] == null);
        assert(a6[aliceFpr] == null);
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

        val network = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cycle.pgp")
        println("Network contains " + network.nodes.size + " nodes with " + network.numberOfEdges + " edges built from " + network.numberOfSignatures + " signatures.")
        val q = Query(network, Roots(), false)

        val a1 = q.backwardPropagate(frankFpr, frankUid, false, IdempotentCertificationFilter());

        checkResult(a1[edFpr]!!, 0, 120, listOf(edFpr, frankFpr));
        checkResult(a1[daveFpr]!!, 0, 30, listOf(daveFpr, edFpr, frankFpr));
        checkResult(a1[carolFpr]!!, 0, 30, listOf(carolFpr, daveFpr, edFpr, frankFpr));
        checkResult(a1[bobFpr]!!, 0, 30, listOf(bobFpr, carolFpr, daveFpr, edFpr, frankFpr));
        assert(a1[aliceFpr] == null)

        val a2 = q.backwardPropagate(frankFpr, frankUid, false, IdempotentCertificationFilter());

        checkResult(a2[edFpr]!!, 0, 120, listOf(edFpr, frankFpr));
        checkResult(a2[daveFpr]!!, 0, 30, listOf(daveFpr, edFpr, frankFpr));
        checkResult(a2[carolFpr]!!, 0, 30, listOf(carolFpr, daveFpr, edFpr, frankFpr));
        checkResult(a2[bobFpr]!!, 0, 30, listOf(bobFpr, carolFpr, daveFpr, edFpr, frankFpr));
        assert(a2[aliceFpr] == null)

        val a3 = q.backwardPropagate(edFpr, edUid, false, IdempotentCertificationFilter());

        assert(a3[frankFpr] == null)
        checkResult(a3[daveFpr]!!, 1, 30, listOf(daveFpr, edFpr));
        checkResult(a3[carolFpr]!!, 1, 30, listOf(carolFpr, daveFpr, edFpr));
        checkResult(a3[bobFpr]!!, 1, 30, listOf(bobFpr, carolFpr, daveFpr, edFpr));
        checkResult(a3[aliceFpr]!!, 0, 30, listOf(aliceFpr, bobFpr, carolFpr, daveFpr, edFpr));

        val a4 = q.backwardPropagate(carolFpr, carolUid, false, IdempotentCertificationFilter());

        assert(a4[frankFpr] == null);
        assert(a4[edFpr] == null);
        checkResult(a4[daveFpr]!!, DEPTH_UNCONSTRAINED, 90, listOf(daveFpr, bobFpr, carolFpr));
        checkResult(a4[bobFpr]!!, DEPTH_UNCONSTRAINED, 90, listOf(bobFpr, carolFpr));
        // The backward propagation algorithm doesn't know that alice
        // is not reachable from the root (dave).
        checkResult(a4[aliceFpr]!!, 2, 90, listOf(aliceFpr, bobFpr, carolFpr));

    }

    @Test
    fun cliques() {
        val root_fpr = Fingerprint("D2B0C3835C01B0C120BC540DA4AA8F880BA512B5")
        val root_uid = "<root@example.org>"

        val a_0_fpr = Fingerprint("363082E9EEB22E50AD303D8B1BFE9BA3F4ABD40E")
        val a_0_uid = "<a-0@example.org>"

        val a_1_fpr = Fingerprint("7974C04E8D5B540D23CD4E62DDFA779D91C69894")
        val a_1_uid = "<a-1@example.org>"

        val b_0_fpr = Fingerprint("25D8EAAB894705BB64D4A6A89649EF81AEFE5162")
        val b_0_uid = "<b-0@example.org>"

        val b_1_fpr = Fingerprint("46D2F5CED9BD3D63A11DDFEE1BA019506BE67FBB")
        val b_1_uid = "<b-1@example.org>"

        val c_0_fpr = Fingerprint("A0CD87582C21743C0E30637F7FADB1C3FEFBFE59")
        val c_0_uid = "<c-0@example.org>"

        val c_1_fpr = Fingerprint("5277C14F9D37A0F4D615DD9CCDCC1AC8464C8FE5")
        val c_1_uid = "<c-1@example.org>"

        val d_0_fpr = Fingerprint("C24CC09102D22E38E8393C55166982561E140C03")
        val d_0_uid = "<d-0@example.org>"

        val d_1_fpr = Fingerprint("7A80DB5330B7D900D5BD1F82EAD72FF7914078B2")
        val d_1_uid = "<d-1@example.org>"

        val e_0_fpr = Fingerprint("D1E9F85CEF6271699FBDE5AB26EFE0E035AC522E")
        val e_0_uid = "<e-0@example.org>"

        val f_0_fpr = Fingerprint("C0FFAEDEF0928B181265775A222B480EB43E0AFF")
        val f_0_uid = "<f-0@example.org>"

        val target_fpr = Fingerprint("CE22ECD282F219AA99598BA3B58A7DA61CA97F55")
        val target_uid = "<target@example.org>"


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cliques.pgp")
        val q1 = Query(n1, Roots(), false)

        val a1 = q1.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        checkResult(a1[root_fpr]!!, 90, 120,
                listOf(root_fpr,
                        a_0_fpr,
                        a_1_fpr,
                        b_0_fpr,
                        b_1_fpr,
                        c_0_fpr,
                        c_1_fpr,
                        d_0_fpr,
                        d_1_fpr,
                        e_0_fpr,
                        f_0_fpr,
                        target_fpr));


        val n2 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cliques-local-optima.pgp")
        val q2 = Query(n2, Roots(), false)

        val a2 = q2.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        checkResult(a2[root_fpr]!!,
                93, 30,
                listOf(root_fpr,
                        b_0_fpr,
                        b_1_fpr,
                        c_0_fpr,
                        c_1_fpr,
                        d_0_fpr,
                        d_1_fpr,
                        e_0_fpr,
                        f_0_fpr,
                        target_fpr));

        val n3 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/cliques-local-optima-2.pgp")
        val q3 = Query(n3, Roots(), false)

        val a3 = q3.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        checkResult(a3[root_fpr]!!, 94, 30,
                listOf(root_fpr,
                        b_0_fpr,
                        b_1_fpr,
                        c_1_fpr,
                        d_0_fpr,
                        d_1_fpr,
                        e_0_fpr,
                        f_0_fpr,
                        target_fpr));

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
        val q1 = Query(n1, Roots(), false)


        val a1 = q1.backwardPropagate(isaacFpr, isaacUid, false, IdempotentCertificationFilter());

        checkResult(a1[aliceFpr]!!, 0, 60, listOf(aliceFpr, bobFpr, georgeFpr, henryFpr, isaacFpr));
        assert(a1[carolFpr] == null)
        assert(a1[jennyFpr] == null)


        val a2 = q1.backwardPropagate(henryFpr, henryUid, false, IdempotentCertificationFilter());

        // The backward propagation algorithm doesn't know that jenny
        // is not reachable from the root (alice).
        checkResult(a2[jennyFpr]!!, 0, 100, listOf(jennyFpr, georgeFpr, henryFpr));
    }

    @Test
    fun local_optima() {
        val alice_fpr = Fingerprint("EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8")
        val alice_uid = "<alice@example.org>"

        val bob_fpr = Fingerprint("89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F")
        val bob_uid = "<bob@example.org>"
        // Certified by: EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8
        // Certified by: EAAE12F98D39F38BF0D1B4C5C46A428ADEFBB2F8

        val carol_fpr = Fingerprint("E9DF94E389F529F8EF6AA223F6CC1F8544C0874D")
        val carol_uid = "<carol@example.org>"
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

        val dave_fpr = Fingerprint("C2F822F17B68E946853A2DCFF55541D89F27F88B")
        val dave_uid = "<dave@example.org>"
        // Certified by: E9DF94E389F529F8EF6AA223F6CC1F8544C0874D
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

        val ellen_fpr = Fingerprint("70507A9058A57FEAE18CC3CE6A398AC9051D9CA8")
        val ellen_uid = "<ellen@example.org>"
        // Certified by: C2F822F17B68E946853A2DCFF55541D89F27F88B
        // Certified by: C2F822F17B68E946853A2DCFF55541D89F27F88B
        // Certified by: E9DF94E389F529F8EF6AA223F6CC1F8544C0874D

        val francis_fpr = Fingerprint("D8DDA78A2297CA3C35B9377577E8B54B9350C082")
        val francis_uid = "<francis@example.org>"
        // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8
        // Certified by: 89C7A9FB7236A77ABBE4F29CB8180FBF6382F90F

        val georgina_fpr = Fingerprint("C5D1B22FEC75911A04E1A5DC75B66B994E70ADE2")
        val georgina_uid = "<georgina@example.org>"
        // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8

        val henry_fpr = Fingerprint("F260739E3F755389EFC2FEE67F58AACB661D5120")
        val henry_uid = "<henry@example.org>"
        // Certified by: 70507A9058A57FEAE18CC3CE6A398AC9051D9CA8


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/local-optima.pgp")
        val q = Query(n1, Roots(), false)

        val a1 = q.backwardPropagate(henry_fpr, henry_uid, false, IdempotentCertificationFilter());

        checkResult(a1[alice_fpr]!!, 0, 100, listOf(alice_fpr, bob_fpr, carol_fpr, ellen_fpr, henry_fpr));
        checkResult(a1[bob_fpr]!!, 0, 100, listOf(bob_fpr, carol_fpr, ellen_fpr, henry_fpr));
        checkResult(a1[carol_fpr]!!, 0, 100, listOf(carol_fpr, ellen_fpr, henry_fpr));
        checkResult(a1[dave_fpr]!!, 0, 50, listOf(dave_fpr, ellen_fpr, henry_fpr));
        checkResult(a1[ellen_fpr]!!, 0, 120, listOf(ellen_fpr, henry_fpr));
        assert(a1[francis_fpr] == null)
        assert(a1[georgina_fpr] == null)

        val a2 = q.backwardPropagate(francis_fpr, francis_uid, false, IdempotentCertificationFilter());

        // Recall: given a choice, we prefer the forward pointer that
        // has the least depth.
        checkResult(a2[alice_fpr]!!, 149, 75, listOf(alice_fpr, bob_fpr, francis_fpr));
        checkResult(a2[bob_fpr]!!, 200, 75, listOf(bob_fpr, francis_fpr));
        checkResult(a2[carol_fpr]!!, 49, 100, listOf(carol_fpr, ellen_fpr, francis_fpr));
        checkResult(a2[dave_fpr]!!, 99, 50, listOf(dave_fpr, ellen_fpr, francis_fpr));
        checkResult(a2[ellen_fpr]!!, 100, 120, listOf(ellen_fpr, francis_fpr));
        assert(a2[georgina_fpr] == null)
        assert(a2[henry_fpr] == null)
    }

    @Test
    fun best_via_root() {
        val alice_fpr = Fingerprint("B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB")
        val alice_uid = "<alice@example.org>"

        val bob_fpr = Fingerprint("6A8B9EC7D0A1B297B5D4A7A1C048DFF96601D9BD")
        val bob_uid = "<bob@example.org>"
        // Certified by: B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB

        val carol_fpr = Fingerprint("77A6F7D4BEE0369F70B249579D2987669F792B35")
        val carol_uid = "<carol@example.org>"
        // Certified by: 6A8B9EC7D0A1B297B5D4A7A1C048DFF96601D9BD

        val target_fpr = Fingerprint("2AB08C06FC795AC26673B23CAD561ABDCBEBFDF0")
        val target_uid = "<target@example.org>"
        // Certified by: 77A6F7D4BEE0369F70B249579D2987669F792B35
        // Certified by: 56D44411F982758169E4681B402E8D5D9D7D6567

        val yellow_fpr = Fingerprint("86CB4639D1FE096BA941D05822B8AF50198C49DD")
        val yellow_uid = "<yellow@example.org>"
        // Certified by: B95FF5B1D055D26F758FD4E3BF12C4D1D28FDFFB

        val zebra_fpr = Fingerprint("56D44411F982758169E4681B402E8D5D9D7D6567")
        val zebra_uid = "<zebra@example.org>"
        // Certified by: 86CB4639D1FE096BA941D05822B8AF50198C49DD


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/best-via-root.pgp")
        val q1 = Query(n1, Roots(), false)

        val a1 = q1.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        checkResult(a1[bob_fpr]!!, 9, 120, listOf(bob_fpr, carol_fpr, target_fpr));
        checkResult(a1[carol_fpr]!!, 10, 120, listOf(carol_fpr, target_fpr));
        checkResult(a1[alice_fpr]!!, 8, 120, listOf(alice_fpr, bob_fpr, carol_fpr, target_fpr));

        val a2 = q1.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        checkResult(a2[alice_fpr]!!, 8, 120, listOf(alice_fpr, bob_fpr, carol_fpr, target_fpr));
        checkResult(a2[bob_fpr]!!, 9, 120, listOf(bob_fpr, carol_fpr, target_fpr));
        checkResult(a2[carol_fpr]!!, 10, 120, listOf(carol_fpr, target_fpr));


        // Again, but this time we specify the roots.
        val q2 = Query(n1, Roots(listOf(Root(alice_fpr, 120))), false)
        val a3 = q2.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        checkResult(a3[alice_fpr]!!, 8, 120, listOf(alice_fpr, bob_fpr, carol_fpr, target_fpr));

        // As seen above, the best path from Alice to the target is
        // via Bob.  But, when both Alice and Bob are both fully
        // trusted roots, the returned path is not via Bob, but one
        // that is less optimal.
        val q3 = Query(n1, Roots(listOf(
                Root(alice_fpr, 120),
                Root(bob_fpr, 120))),
                false)
        val a4 = q3.backwardPropagate(target_fpr, target_uid, false, IdempotentCertificationFilter());

        checkResult(a4[bob_fpr]!!, 9, 120, listOf(bob_fpr, carol_fpr, target_fpr));
        checkResult(a4[alice_fpr]!!, 8, 50, listOf(alice_fpr, yellow_fpr, zebra_fpr, target_fpr));
    }

    @Test
    fun regex_1() {
        val alice_fpr = Fingerprint("3AD1F297E4B150F75DBFC43476FB81BFE0665C3A")
        val alice_uid = "<alice@some.org>"

        val bob_fpr = Fingerprint("20C812117FB2A3940EAE9160FEE6B4E47A096FD1")
        val bob_uid = "<bob@example.org>"
        // Certified by: 3AD1F297E4B150F75DBFC43476FB81BFE0665C3A

        val carol_fpr = Fingerprint("BC30978345D789CADECDE492F54B42E1625E1A1D")
        val carol_uid = "<carol@example.org>"
        // Certified by: 20C812117FB2A3940EAE9160FEE6B4E47A096FD1

        val dave_fpr = Fingerprint("319810FAD46CBE96DAD7F1F5B014902592999B21")
        val dave_uid = "<dave@other.org>"
        // Certified by: 20C812117FB2A3940EAE9160FEE6B4E47A096FD1

        val ed_fpr = Fingerprint("23D7418EA0C6A42A54C32DBE8D4FE4911ED08467")
        val ed_uid = "<ed@example.org>"
        // Certified by: 319810FAD46CBE96DAD7F1F5B014902592999B21

        val frank_fpr = Fingerprint("7FAE20D68EE87F74368AF275A0C40E741FC1C50F")
        val frank_uid = "<frank@other.org>"
        // Certified by: 319810FAD46CBE96DAD7F1F5B014902592999B21


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/regex-1.pgp")
        val q1 = Query(n1, Roots(), false)

        // alice as root.
        val a1 = q1.backwardPropagate(bob_fpr, bob_uid, false, IdempotentCertificationFilter());
        checkResult(a1[alice_fpr]!!, 3, 100, listOf(alice_fpr, bob_fpr));

        val a2 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter());
        checkResult(a2[alice_fpr]!!, 1, 100, listOf(alice_fpr, bob_fpr, carol_fpr));

        val a3 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter());
        // There is no path, because dave@example.org does not match
        // the constraint on bob (domain: example.org).
        assert(a3[alice_fpr] == null)

        val a4 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        // There is no path, because ed@example.org does not match
        // the constraint on dave (domain: other.org).
        assert(a4[alice_fpr] == null)

        val a5 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())

        // There is no path, because frank@other.org does not match
        // the constraint on bob (domain: example.org).
        assert(a5[alice_fpr] == null)


        // bob as root.
        val a6 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        checkResult(a6[bob_fpr]!!, 1, 100, listOf(bob_fpr, carol_fpr))

        val a7 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a7[bob_fpr]!!, 1, 100, listOf(bob_fpr, dave_fpr))

        val a8 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())

        // There is no path, because ed@example.org does not match
        // the constraint on dave (domain: other.org).
        assert(a8[bob_fpr] == null)

        val a9 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(a9[bob_fpr]!!, 0, 100, listOf(bob_fpr, dave_fpr, frank_fpr))


        // dave as root.
        val a10 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        checkResult(a10[dave_fpr]!!, 1, 100, listOf(dave_fpr, ed_fpr));

        val a11 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(a11[dave_fpr]!!, 1, 100, listOf(dave_fpr, frank_fpr))
    }

    @Test
    fun regex_2() {
        val alice_fpr = Fingerprint("5C396C920399898461F17CB747FDBF3EB3453919")
        val alice_uid = "<alice@some.org>"

        val bob_fpr = Fingerprint("584D195AD89CE0354D2CCBAEBCDD9EBC09692780")
        val bob_uid = "<bob@some.org>"
        // Certified by: 5C396C920399898461F17CB747FDBF3EB3453919

        val carol_fpr = Fingerprint("FC7A96D4810D0CF477031956AED58C644370C183")
        val carol_uid = "<carol@other.org>"
        // Certified by: 584D195AD89CE0354D2CCBAEBCDD9EBC09692780

        val dave_fpr = Fingerprint("58077E659732526C1B8BF9837EFC0EDE07B506A8")
        val dave_uid = "<dave@their.org>"
        // Certified by: FC7A96D4810D0CF477031956AED58C644370C183

        val ed_fpr = Fingerprint("36089C49F18BF6FC6BCA35E3BB85877766C009E4")
        val ed_uid = "<ed@example.org>"
        // Certified by: 58077E659732526C1B8BF9837EFC0EDE07B506A8


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/regex-2.pgp")
        val q1 = Query(n1, Roots(), false)


        val a1 = q1.backwardPropagate(bob_fpr, bob_uid, false, IdempotentCertificationFilter())
        checkResult(a1[alice_fpr]!!, 7, 100, listOf(alice_fpr, bob_fpr))

        val a2 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        // There is no path, because carol@other.org does not match
        // the constraint on carol (domain: example.org).
        assert(a2[alice_fpr] == null)

        val a3 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        // There is no path, because dave@their.org does not match
        // the constraint on carol (domain: example.org).
        assert(a3[alice_fpr] == null)

        val a4 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        checkResult(a4[alice_fpr]!!, 4, 100, listOf(alice_fpr, bob_fpr, carol_fpr, dave_fpr, ed_fpr))


        val a5 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter());
        // There is no path, because carol@other.org does not match
        // the constraint on carol (domain: example.org).
        assert(a5[bob_fpr] == null)

        val a6 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        // There is no path, because dave@their.org does not match
        // the constraint on carol (domain: example.org).
        assert(a6[bob_fpr] == null)

        val a7 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        checkResult(a7[bob_fpr]!!, 5, 100, listOf(bob_fpr, carol_fpr, dave_fpr, ed_fpr))

        val a8 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a8[carol_fpr]!!, 7, 100, listOf(carol_fpr, dave_fpr));

        val a9 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        checkResult(a9[carol_fpr]!!, 6, 100, listOf(carol_fpr, dave_fpr, ed_fpr))
    }

    @Test
    fun regex_3() {
        val alice_fpr = Fingerprint("D8CFEBBA006E2ED57CF45CC413F0BAE09D94FE4E")
        val alice_uid = "<alice@some.org>"

        val bob_fpr = Fingerprint("A75DC1A1EDA5282F3A7381B51824E46BBCC801F0")
        val bob_uid = "<bob@example.org>"
        // Certified by: D8CFEBBA006E2ED57CF45CC413F0BAE09D94FE4E

        val carol_fpr = Fingerprint("4BCD4325BDACA452F0301227A30CB4BCC329E769")
        val carol_uid = "<carol@example.org>"
        // Certified by: A75DC1A1EDA5282F3A7381B51824E46BBCC801F0

        val dave_fpr = Fingerprint("2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380")
        val dave_uid = "<dave@other.org>"
        // Certified by: A75DC1A1EDA5282F3A7381B51824E46BBCC801F0

        val ed_fpr = Fingerprint("F645D081F480BE26C7D2C84D941B3E2CE53FAF16")
        val ed_uid = "<ed@example.org>"
        // Certified by: 2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380

        val frank_fpr = Fingerprint("AFAB11F1A37FD20C85CF8093F4941D1A0EC5749F")
        val frank_uid = "<frank@other.org>"
        // Certified by: 2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380

        val george_fpr = Fingerprint("D01C8752D9BA9F3F5F06B21F394E911938D6DB0A")
        val george_uid = "<george@their.org>"
        // Certified by: 2E1AAA8D9A22C94ACCA362A22B34031CD5CB9380

        val henry_fpr = Fingerprint("B99A8696FD820192CEEE285D3A253E49F1D97109")
        val henry_uid = "<henry@their.org>"
        // Certified by: A75DC1A1EDA5282F3A7381B51824E46BBCC801F0


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/regex-3.pgp")
        val q1 = Query(n1, Roots(), false)


        // alice as root.
        val a1 = q1.backwardPropagate(bob_fpr, bob_uid, false, IdempotentCertificationFilter())
        checkResult(a1[alice_fpr]!!, 3, 100, listOf(alice_fpr, bob_fpr))

        val a2 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        checkResult(a2[alice_fpr]!!, 1, 100, listOf(alice_fpr, bob_fpr, carol_fpr))

        val a3 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a3[alice_fpr]!!, 1, 100, listOf(alice_fpr, bob_fpr, dave_fpr))

        val a4 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        // There is no path, because ed@example.org does not match
        // the constraint on dave (domain: other.org).
        assert(a4[alice_fpr] == null)

        val a5 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(a5[alice_fpr]!!, 0, 100, listOf(alice_fpr, bob_fpr, dave_fpr, frank_fpr))

        val a6 = q1.backwardPropagate(george_fpr, george_uid, false, IdempotentCertificationFilter())
        assert(a6[alice_fpr] == null)

        val a7 = q1.backwardPropagate(henry_fpr, henry_uid, false, IdempotentCertificationFilter())
        assert(a7[alice_fpr] == null)


        // bob as root.
        val a8 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        checkResult(a8[bob_fpr]!!, 1, 100, listOf(bob_fpr, carol_fpr))

        val a9 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a9[bob_fpr]!!, 1, 100, listOf(bob_fpr, dave_fpr))

        val a10 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        // There is no path, because ed@example.org does not match
        // the constraint on dave (domain: other.org).
        assert(a10[bob_fpr] == null)

        val a11 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(a11[bob_fpr]!!, 0, 100, listOf(bob_fpr, dave_fpr, frank_fpr))

        val a12 = q1.backwardPropagate(george_fpr, george_uid, false, IdempotentCertificationFilter())
        checkResult(a12[bob_fpr]!!, 0, 100, listOf(bob_fpr, dave_fpr, george_fpr))

        val a13 = q1.backwardPropagate(henry_fpr, henry_uid, false, IdempotentCertificationFilter())
        checkResult(a13[bob_fpr]!!, 1, 100, listOf(bob_fpr, henry_fpr))


        // dave as root.
        val a14 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        checkResult(a14[dave_fpr]!!, 1, 100, listOf(dave_fpr, ed_fpr))

        val a15 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(a15[dave_fpr]!!, 1, 100, listOf(dave_fpr, frank_fpr))

        val a16 = q1.backwardPropagate(george_fpr, george_uid, false, IdempotentCertificationFilter())
        checkResult(a16[dave_fpr]!!, 1, 100, listOf(dave_fpr, george_fpr))
    }

    @Test
    fun multiple_userids_1() {
        val alice_fpr = Fingerprint("2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA")
        val alice_uid = "<alice@example.org>"

        val bob_fpr = Fingerprint("03182611B91B1E7E20B848E83DFC151ABFAD85D5")
        val bob_uid = "<bob@other.org>"
        // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA
        val bob_some_org_uid = "<bob@some.org>"
        // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA

        val carol_fpr = Fingerprint("9CA36907B46FE7B6B9EE9601E78064C12B6D7902")
        val carol_uid = "<carol@example.org>"
        // Certified by: 03182611B91B1E7E20B848E83DFC151ABFAD85D5

        val dave_fpr = Fingerprint("C1BC6794A6C6281B968A6A41ACE2055D610CEA03")
        val dave_uid = "<dave@other.org>"
        // Certified by: 9CA36907B46FE7B6B9EE9601E78064C12B6D7902


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/multiple-userids-1.pgp")
        println(n1)

        val q1 = Query(n1, Roots(), false)


        val a1 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        checkResult(a1[alice_fpr]!!, 0, 70, listOf(alice_fpr, bob_fpr, carol_fpr))

        val a2 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a2[alice_fpr]!!, 0, 50, listOf(alice_fpr, bob_fpr, carol_fpr, dave_fpr))
    }

    @Test
    fun multiple_userids_2() {
        val alice_fpr = Fingerprint("F1C99C4019837703DD17C45440F8A0141DF278EA")
        val alice_uid = "<alice@example.org>"

        val bob_fpr = Fingerprint("5528B9E5DAFC519ED2E37F0377B332E4111456CB")
        val bob_uid = "<bob@other.org>"
        // Certified by: F1C99C4019837703DD17C45440F8A0141DF278EA
        val bob_some_org_uid = "<bob@some.org>"
        // Certified by: F1C99C4019837703DD17C45440F8A0141DF278EA

        val carol_fpr = Fingerprint("6F8291428420AB53576BAB4BEFF6477D3E348D71")
        val carol_uid = "<carol@example.org>"
        // Certified by: 5528B9E5DAFC519ED2E37F0377B332E4111456CB

        val dave_fpr = Fingerprint("62C57D90DAD253DEA01D5A86C7382FD6285C18F0")
        val dave_uid = "<dave@other.org>"
        // Certified by: 6F8291428420AB53576BAB4BEFF6477D3E348D71

        val ed_fpr = Fingerprint("0E974D0ACBA0C4D8F51D7CF68F048FF83B173504")
        val ed_uid = "<ed@example.org>"
        // Certified by: 6F8291428420AB53576BAB4BEFF6477D3E348D71

        val frank_fpr = Fingerprint("5BEE3D41F85B2FCBC300DE4E18CB2BDA65465F03")
        val frank_uid = "<frank@other.org>"
        // Certified by: 5528B9E5DAFC519ED2E37F0377B332E4111456CB


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/multiple-userids-2.pgp")
        val q1 = Query(n1, Roots(), false)


        val a1 = q1.backwardPropagate(bob_fpr, bob_uid, false, IdempotentCertificationFilter())
        checkResult(a1[alice_fpr]!!, DEPTH_UNCONSTRAINED, 70, listOf(alice_fpr, bob_fpr))

        val a2 = q1.backwardPropagate(bob_fpr, bob_some_org_uid, false, IdempotentCertificationFilter())
        checkResult(a2[alice_fpr]!!, 1, 50, listOf(alice_fpr, bob_fpr))

        val a3 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        checkResult(a3[alice_fpr]!!, 0, 50, listOf(alice_fpr, bob_fpr, carol_fpr))

        val a4 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a4[alice_fpr]!!, 0, 70, listOf(alice_fpr, bob_fpr, carol_fpr, dave_fpr))

        val a5 = q1.backwardPropagate(ed_fpr, ed_uid, false, IdempotentCertificationFilter())
        assert(a5[alice_fpr] == null)

        val a6 = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(a6[alice_fpr]!!, 0, 70, listOf(alice_fpr, bob_fpr, frank_fpr))
    }

    @Test
    fun multiple_certifications_1() {
        val alice_fpr = Fingerprint("9219941467AA737C6EC1207959A2CEFC112C359A")
        val alice_uid = "<alice@example.org>"

        val bob_fpr = Fingerprint("72CAA0F0A4A020F5FA20CD8CB5CC04473AA88123")
        val bob_uid = "<bob@example.org>"
        // Certified by: 9219941467AA737C6EC1207959A2CEFC112C359A
        // Certified by: 9219941467AA737C6EC1207959A2CEFC112C359A
        // Certified by: 9219941467AA737C6EC1207959A2CEFC112C359A

        val carol_fpr = Fingerprint("853304031E7B0B116BBD0B398734F11945313904")
        val carol_uid = "<carol@example.org>"
        // Certified by: 72CAA0F0A4A020F5FA20CD8CB5CC04473AA88123

        val dave_fpr = Fingerprint("4C77ABDBE4F855E0C3C7A7D549F6B2BFDA83E424")
        val dave_uid = "<dave@example.org>"
        // Certified by: 853304031E7B0B116BBD0B398734F11945313904


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/multiple-certifications-1.pgp")
        println(n1)

        val q1 = Query(n1, Roots(), false)


        val a1 = q1.backwardPropagate(carol_fpr, carol_uid, false, IdempotentCertificationFilter())
        checkResult(a1[alice_fpr]!!, 0, 70, listOf(alice_fpr, bob_fpr, carol_fpr))

        val a2 = q1.backwardPropagate(dave_fpr, dave_uid, false, IdempotentCertificationFilter())
        checkResult(a2[alice_fpr]!!, 0, 50, listOf(alice_fpr, bob_fpr, carol_fpr, dave_fpr))
    }

    @Test
    fun multiple_userids_3() {
        val alice_fpr = Fingerprint("DA3CFC60BD4B8835702A66782C7A431946C12DF7")
        val alice_uid = "<alice@example.org>"

        val bob_fpr = Fingerprint("28C108707090FCDFF630D1E141FB02F0E397D55E")
        val bob_uid = "<bob@other.org>"
        // Certified by: DA3CFC60BD4B8835702A66782C7A431946C12DF7
        val bob_some_org_uid = "<bob@some.org>"
        // Certified by: DA3CFC60BD4B8835702A66782C7A431946C12DF7
        val bob_third_org_uid = "<bob@third.org>"

        val carol_fpr = Fingerprint("9FB1D2F41AB5C478378E728C8DD5A5A434EEAAB8")
        val carol_uid = "<carol@example.org>"
        // Certified by: 28C108707090FCDFF630D1E141FB02F0E397D55E

        val dave_fpr = Fingerprint("0C131F8959F45D08B6136FDAAD2E16A26F73D48E")
        val dave_uid = "<dave@example.org>"
        // Certified by: 28C108707090FCDFF630D1E141FB02F0E397D55E

        val ed_fpr = Fingerprint("296935FAE420CCCF3AEDCEC9232BFF0AE9A7E5DB")
        val ed_uid = "<ed@example.org>"
        // Certified by: 0C131F8959F45D08B6136FDAAD2E16A26F73D48E

        val frank_fpr = Fingerprint("A72AA1B7D9D8CB04D988F1520A404E37A7766608")
        val frank_uid = "<frank@example.org>"
        // Certified by: 9FB1D2F41AB5C478378E728C8DD5A5A434EEAAB8
        // Certified by: 296935FAE420CCCF3AEDCEC9232BFF0AE9A7E5DB


        val n1 = getNetwork("/home/heiko/src/sequoia-wot/tests/data/multiple-userids-3.pgp")
        val q1 = Query(n1, Roots(), false)


        val auth = q1.backwardPropagate(frank_fpr, frank_uid, false, IdempotentCertificationFilter())
        checkResult(auth[alice_fpr]!!, 0, 20, listOf(alice_fpr, bob_fpr, carol_fpr, frank_fpr))
    }

}