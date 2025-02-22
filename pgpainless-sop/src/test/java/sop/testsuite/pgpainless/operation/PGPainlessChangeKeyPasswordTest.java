// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.util.Passphrase;
import sop.SOP;
import sop.testsuite.TestData;
import sop.testsuite.operation.ChangeKeyPasswordTest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class PGPainlessChangeKeyPasswordTest extends ChangeKeyPasswordTest {

    @ParameterizedTest
    @MethodSource("provideInstances")
    public void changePasswordOfKeyWithSeparateSubkeyPasswords(SOP sop) throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .build();
        Iterator<PGPPublicKey> keys = secretKeys.getPublicKeys();
        long primaryKeyId = keys.next().getKeyID();
        long signingKeyId = keys.next().getKeyID();
        long encryptKeyId = keys.next().getKeyID();

        String p1 = "sw0rdf1sh";
        String p2 = "0r4ng3";
        String p3 = "dr4g0n";

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .changeSubKeyPassphraseFromOldPassphrase(primaryKeyId, Passphrase.emptyPassphrase())
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword(p1))
                .changeSubKeyPassphraseFromOldPassphrase(signingKeyId, Passphrase.emptyPassphrase())
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword(p2))
                .changeSubKeyPassphraseFromOldPassphrase(encryptKeyId, Passphrase.emptyPassphrase())
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword(p3))
                .done();

        String p4 = "m0nk3y";

        byte[] keyWithNewPassword = sop.changeKeyPassword()
                .oldKeyPassphrase(p1)
                .oldKeyPassphrase(p2)
                .oldKeyPassphrase(p3)
                .newKeyPassphrase(p4)
                .keys(secretKeys.getEncoded())
                .getBytes();
        byte[] cert = sop.extractCert().key(keyWithNewPassword).getBytes();

        byte[] signedAndEncrypted = sop.encrypt()
                .signWith(keyWithNewPassword)
                .withKeyPassword(p4)
                .withCert(cert)
                .plaintext(TestData.PLAINTEXT.getBytes(StandardCharsets.UTF_8))
                .getBytes();
        byte[] plaintext = sop.decrypt()
                .verifyWithCert(cert)
                .withKey(keyWithNewPassword)
                .withKeyPassword(p4)
                .ciphertext(signedAndEncrypted)
                .toByteArrayAndResult().getBytes();

        assertArrayEquals(TestData.PLAINTEXT.getBytes(StandardCharsets.UTF_8), plaintext);
    }
}
