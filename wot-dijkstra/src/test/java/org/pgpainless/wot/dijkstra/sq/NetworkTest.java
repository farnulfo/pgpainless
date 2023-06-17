package org.pgpainless.wot.dijkstra.sq;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class NetworkTest {

    @Test
    public void testEmptyNetworkIsEmpty() {
        ReferenceTime referenceTime = ReferenceTime.now();
        Network network = Network.empty(referenceTime);

        assertTrue(network.getNodes().isEmpty());
        assertTrue(network.getEdges().isEmpty());
        assertTrue(network.getReverseEdges().isEmpty());
        assertEquals(referenceTime, network.getReferenceTime());
    }

    @Test
    public void testNetworkFromCertificates() {
        ReferenceTime referenceTime = ReferenceTime.now();
    }


}
