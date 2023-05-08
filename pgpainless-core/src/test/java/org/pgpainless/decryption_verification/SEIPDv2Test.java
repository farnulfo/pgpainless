// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class SEIPDv2Test {

    public static final String CIPHERTEXT_EAX = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14\n" +
            "KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq\n" +
            "pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1\n" +
            "QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=\n" +
            "-----END PGP MESSAGE-----\n";

    public static final String CIPHERTEXT_OCB = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl\n" +
            "ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM\n" +
            "WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0\n" +
            "K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==\n" +
            "-----END PGP MESSAGE-----\n";

    public static final String CIPHERTEXT_GCM = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa\n" +
            "v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax\n" +
            "Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS\n" +
            "+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==\n" +
            "-----END PGP MESSAGE-----\n";

    public static final String PASSWORD = "password";
    public static final String PLAINTEXT = "Hello, world!";

    @Test
    public void testDecryptEax() throws PGPException, IOException {
        testDecrypt(CIPHERTEXT_EAX);
    }

    @Test
    public void testDecryptOcb() throws PGPException, IOException {
        testDecrypt(CIPHERTEXT_OCB);
    }

    @Test
    public void testDecryptGcm() throws PGPException, IOException {
        testDecrypt(CIPHERTEXT_GCM);
    }

    private void testDecrypt(String ciphertext) throws PGPException, IOException {
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ciphertext.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get()
                        .addDecryptionPassphrase(Passphrase.fromPassword(PASSWORD)));
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, plaintext);
        decryptionStream.close();

        assertArrayEquals(PLAINTEXT.getBytes(StandardCharsets.UTF_8), plaintext.toByteArray());
    }
}
