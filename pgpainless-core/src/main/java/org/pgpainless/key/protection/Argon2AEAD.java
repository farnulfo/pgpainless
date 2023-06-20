package org.pgpainless.key.protection;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.algorithm.AEADAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.Passphrase;

public class Argon2AEAD implements KeyRingProtectionSettings {

    private final S2K.Argon2Params parameters;
    private final SymmetricKeyAlgorithm encryptionAlgorithm;
    private final AEADAlgorithm aeadAlgorithm;

    public Argon2AEAD() {
        this(S2K.Argon2Params.universallyRecommendedParameters(), SymmetricKeyAlgorithm.AES_256, AEADAlgorithm.OCB);
    }

    public Argon2AEAD(S2K.Argon2Params parameters, SymmetricKeyAlgorithm encryptionAlgorithm, AEADAlgorithm aeadAlgorithm) {
        this.parameters = parameters;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
    }

    @Override
    public PBESecretKeyEncryptor getEncryptor(Passphrase passphrase) throws PGPException {
        // TODO: Implement.
        return null;
    }
}
