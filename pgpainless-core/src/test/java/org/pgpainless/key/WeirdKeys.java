// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.util.Strings;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

/**
 * This class contains a set of slightly out of spec or weird keys.
 * Those are used to test whether implementations behave correctly when dealing with such keys.
 *
 * @see <a href="https://gitlab.com/sequoia-pgp/weird-keys">Original Source</a>
 */
public class WeirdKeys {

    /**
     * This key has two encryption subkeys, both "may be used to encrypt
     * communications" (key flag 0x04), and "may be used to encrypt storage"
     * (key flag 0x08).
     */
    public static final String TWO_CRYPT_SUBKEYS = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 7B71 019D 244B 250E 2D87  B168 AA4C 965A 79FD 159F\n" +
            "Comment: Two Fish <two@example.org>\n" +
            "\n" +
            "lFgEYQ/uqxYJKwYBBAHaRw8BAQdAajnmsfDPTpwJtqsH7yuSSmKzk/v6Q2qXmFOI\n" +
            "ra8YeKgAAQDcKvq5zVAKvurI+qXh80aw3ynIH/JYds+0CtMtZJyEDRKHtBpUd28g\n" +
            "RmlzaCA8dHdvQGV4YW1wbGUub3JnPoh4BBMWCgAgBQJhD+6sAhsDBRYCAwEABAsJ\n" +
            "CAcFFQoJCAsCHgECGQEACgkQqkyWWnn9FZ+v+QEAt3o0BwY1yQZ7W6KNNGFwk5yP\n" +
            "82zK5POtJ8tv1sZIf18BAOqgZU6IzasEIjihbrVmyB6qhxgy41ScKvHSNhAN7vEP\n" +
            "nHsEYQ/urBIIKoZIzj0DAQcCAwRcUEGR3ZdvlXQQSxVLMOi0eLhFqZ09STxjS0kM\n" +
            "7r4llRlVI3jXNYorGmJIXb8xgnyisWLb11FvL1EGT6s7DcSEAwEIBwAA/0u+YdR0\n" +
            "CJhfM2YmtiHv9WYOrN9J1qXuXQuoikeiISimEE2IdQQYFgoAHQUCYQ/urAIbDAUW\n" +
            "AgMBAAQLCQgHBRUKCQgLAh4BAAoJEKpMllp5/RWfatUA/RJrmJaZ7TaDUHZJAgiX\n" +
            "UPgEZw5R675jYfKN4y6YLg2rAP0XWV6T1fmGcxjV//shbP693DlyHrpCfIFHvASl\n" +
            "PofuA5x7BGEP7qwSCCqGSM49AwEHAgMEiBmYN0LnrsgtITA2ZXfCtreq20bsj1mR\n" +
            "nSt2zsFqvy9c3OM18PiT8sgmAUMvS0up9hWtOB1XgA0OwNHzv19uvQMBCAcAAP9o\n" +
            "jX1KuCRPvyeo8GiwUCVdciG7BpsMNxhQlkoyhHt/dw3viHUEGBYKAB0FAmEP7qwC\n" +
            "GwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRCqTJZaef0VnxpOAQClDbWnBpUNflwX\n" +
            "UcT1mUtFABYhDI+yo3DkfHxq/wEZzwD/U4NDtvxAYkX01qPSBfE+u+iQ4GiHya87\n" +
            "aEdm1GVjyQw=\n" +
            "=BlPm\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    public static PGPSecretKeyRing getTwoCryptSubkeysKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(TWO_CRYPT_SUBKEYS);
    }

    /**
     * This key has two encryption subkeys, both "may be used to encrypt
     * communications" (key flag 0x04), and "may be used to encrypt storage"
     * (key flag 0x08).
     */
    public static final String ARCHIVE_COMMS_SUBKEYS = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "xVgEWxjzpRYJKwYBBAHaRw8BAQdA99pRASsejv2MgFMYg6LDPyK3BCT7xXhC2f09\n" +
            "fqT7oQEAAQCouh/2DcFODQGEARwJU3JXvna3ylSGENAxk/0fFmStXQ07zSZCYXJi\n" +
            "YXJhIEJvb2t3b3JtIDxiYXJiYXJhQGV4YW1wbGUub3JnPsJ+BBMWCgAwApsDBYJb\n" +
            "GPOlBYkB3+IAFqEE1IeY6A/QyQJeHtHU084ZkNvzgW8JkNPOGZDb84FvAACnswEA\n" +
            "tRh0mZPid3fMJH0i/Z2mYniJDkjZSlTcyjU71qPbifIA/1rapZ4lSk4x0/spKB6b\n" +
            "DU2On70rFOiHm+Dgn2BiI6gKx10EWxjzpRIKKwYBBAGXVQEFAQEHQDMzo7bN+wEH\n" +
            "8HaSeuhpt6Qbl5fDqjvjXTq46fVLyJFqAwEKCQAA/0wtp9u69jRBfQnZkf/X0Ed3\n" +
            "WbswE4XPremh+UPYYbCwEyrCfgQYFgoAMAKbCAWCWxjzpQWJAd/iABahBNSHmOgP\n" +
            "0MkCXh7R1NPOGZDb84FvCZDTzhmQ2/OBbwAAmN8A+gNLRbqxCfyVxFeUuTRpAM+g\n" +
            "vPxW/x8Wn6EXgYuyzXB0AP4xg/dWdZEaORArLgrFNzeQVxhWwT9LQ0wkKK2MDP7y\n" +
            "DcddBFsY86USCisGAQQBl1UBBQEBB0DCSkkrqL/6JMFuPdhD3VJd35dBIM618Niv\n" +
            "i8gzZWMARAMBCgkAAP93iLDHFbRfBV1J/OIxjjQny2h5XRdjOzFPxYxnDOd1IA6+\n" +
            "wn4EGBYKADACmwQFglsY86UFiQHf4gAWoQTUh5joD9DJAl4e0dTTzhmQ2/OBbwmQ\n" +
            "084ZkNvzgW8AAHv1AP9psIMvVd3G7ha+aITWjj8J+YpJ6Q4MC7fWNJ8jWf7FAAD+\n" +
            "Ki/Tb93AMDlwEMcZsyKj3Oa28tsS1ybS6y3ZSs4wqQs=\n" +
            "=h6sT\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    public static PGPSecretKeyRing getArchiveCommsSubkeysKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(ARCHIVE_COMMS_SUBKEYS);
    }

    @Test
    public void generateCertAndTestWithNonUTF8UserId()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing nakedKey = PGPainless.generateKeyRing().modernKeyRing(null);
        PGPPublicKey pubKey = nakedKey.getPublicKey();
        PGPSecretKey secKey = nakedKey.getSecretKey();
        PGPPrivateKey privKey = UnlockSecretKey.unlockSecretKey(secKey, Passphrase.emptyPassphrase());

        // Non-UTF8 User-ID
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        for (int i = 0xc0; i <= 0xdf; i++) {
            bOut.write(i);
            bOut.write(" ".getBytes());
        }
        byte[] idBytes = bOut.toByteArray();

        // Check that this is in fact not a valid UTF8 String
        assertThrows(IllegalArgumentException.class, () -> Strings.fromUTF8ByteArray(idBytes));

        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        pubKey.getAlgorithm(),
                        HashAlgorithmTags.SHA512));
        sigGen.init(SignatureType.GENERIC_CERTIFICATION.getCode(), privKey);

        // We have to manually generate the signature over the user-ID
        // updateWithKey()
        byte[] keyBytes = pubKey.getPublicKeyPacket().getEncodedContents();
        sigGen.update((byte) 0x99);
        sigGen.update((byte) (keyBytes.length >> 8));
        sigGen.update((byte) (keyBytes.length));
        sigGen.update(keyBytes);

        // Update with ID data
        sigGen.update((byte) 0xb4);
        sigGen.update((byte) (idBytes.length >> 24));
        sigGen.update((byte) (idBytes.length >> 16));
        sigGen.update((byte) (idBytes.length >> 8));
        sigGen.update((byte) (idBytes.length));
        sigGen.update(idBytes);

        PGPSignature signature = sigGen.generate();
        pubKey = PGPPublicKey.addCertification(pubKey, idBytes, signature);

        PGPPublicKeyRing cert = new PGPPublicKeyRing(Collections.singletonList(pubKey));

        // This might fail
        KeyRingInfo info = PGPainless.inspectKeyRing(cert);
        assertTrue(info.getUserIds().isEmpty()); // Malformed ID is ignored
    }
}
