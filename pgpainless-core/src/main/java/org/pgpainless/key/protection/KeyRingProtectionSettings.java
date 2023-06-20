package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.Passphrase;

public interface KeyRingProtectionSettings {

    /**
     * Secure default settings using {@link SymmetricKeyAlgorithm#AES_256}, {@link HashAlgorithm#SHA256}
     * and an iteration count of 65536.
     *
     * @return secure protection settings
     */
    static SaltedAndIteratedS2K saltedAndIterated() {
        return new SaltedAndIteratedS2K(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA256, 0x60);
    }

    static KeyRingProtectionSettings argon2() {
        return new Argon2AEAD();
    }

    /**
     * Return an {@link PBESecretKeyEncryptor} instance using these protection settings.
     *
     * @param passphrase passphrase
     * @return encryptor
     */
    PBESecretKeyEncryptor getEncryptor(Passphrase passphrase) throws PGPException;
}
