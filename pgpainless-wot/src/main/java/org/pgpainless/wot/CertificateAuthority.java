// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import org.bouncycastle.openpgp.PGPPublicKeyRing;

public interface CertificateAuthority {

    /**
     * Returns <pre>true</pre>, if the given binding (certificate and user-id) is correct.
     * Correct means, that the binding is trustworthy.
     *
     * @param certificate OpenPGP certificate
     * @param userId user-id
     * @return binding correctness
     */
    boolean isAuthorized(PGPPublicKeyRing certificate, String userId);

}
