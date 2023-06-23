// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import org.junit.jupiter.api.Test;
import org.pgpainless.wot.testfixtures.TestCertificateStores;
import pgp.certificate_store.exception.BadDataException;

import java.io.IOException;

public class WebOfTrustTest {

    @Test
    public void testWithCrossSignedCertificates()
            throws BadDataException, IOException, InterruptedException {
        WebOfTrustCertificateStore store = TestCertificateStores.disconnectedGraph();
        WebOfTrust wot = new WebOfTrust(store);
        wot.initialize();

        // TODO: Test stuff
    }
}
