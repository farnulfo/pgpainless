package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ReplaceUserIdsTest {

    private static final String ALICE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: C832 FCF6 8A39 435D 1418  182B 3EA3 1C91 627E FA68\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lFgEY6CJSxYJKwYBBAHaRw8BAQdAt1Lkv59sa2VqjaQKx43Gm9ZGqYR5h3K7Esh1\n" +
            "ST+7c9cAAP9yP4ome4FitAIgQlapRHPtHkBQuibKTMugbsxWjuot5Q+itBxBbGlj\n" +
            "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEFAmOgiUsJED6jHJFifvpo\n" +
            "FiEEyDL89oo5Q10UGBgrPqMckWJ++mgCngECmwEFFgIDAQAECwkIBwUVCgkICwKZ\n" +
            "AQAAYHAA/1jEd+GfwOoezakcNAhH1v9nIkLednBevIJlYA3NpU9GAQDG8JxPIKFG\n" +
            "IaAEUneNFiKrNUGXoMETlUb4ulv45TGHCpxdBGOgiUsSCisGAQQBl1UBBQEBB0Cn\n" +
            "w+QFN1c9+czKA4UZzcrGj6qKnixJLIZoNGjfE1y9ewMBCAcAAP9hhOdXzGwri5eU\n" +
            "2GUvzsYENPK1fNVWZhlb44jZhm/0eBJAiHUEGBYKAB0FAmOgiUsCngECmwwFFgID\n" +
            "AQAECwkIBwUVCgkICwAKCRA+oxyRYn76aCX0AQDIrlj3vsFZGiKjyFBFEoiL0Xh/\n" +
            "Gs3tPYk7fpzlf7ek0QD/R1Hp5rGqT/BBYGXcSygFAYIDvpSzdK8LjYAw9Uf63AGc\n" +
            "WARjoIlLFgkrBgEEAdpHDwEBB0C1S700LSMUXz3mwNKV5Eg/dHWQ8og/fJIwnYJr\n" +
            "CZ7zzQAA/1am1K6E2IDvRXGzXtNr8l+tiEjcb3sIgDLd3f/3ZhfgE6iI1QQYFgoA\n" +
            "fQUCY6CJSwKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmOgiUsACgkQ\n" +
            "Fu2wex5ipJZ/owD9EqmdfNZW7H8bUurRD3mlb3s0aKomSISlGqQaJ2p5vsQA+QGD\n" +
            "o96SHr1uXFatKxPTNjtHAc7reXNIiU9zUkHYX34OAAoJED6jHJFifvpok6kBAITS\n" +
            "j93mcCj9kY5kmF0Yy1MfpvUejKvyEmvAp+/SyLwPAP0fphtCBQ2sGyhGwltqdzxa\n" +
            "xW7s6bMcLxWbgQ0XDBY9AA==\n" +
            "=DLVo\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    // Bob <bob@pgpainless.org>
    // Bob <bob@example.org>
    // Bobby (work email) <bobby@openpgp.org>
    private static final String BOB_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 38F3 CB55 C409 7F00 1CF5  5EBC 84B8 BA68 0A84 816A\n" +
            "Comment: Bob <bob@pgpainless.org>\n" +
            "Comment: 2 further identities\n" +
            "\n" +
            "lFgEY6CMehYJKwYBBAHaRw8BAQdA6+fYjOUu6ANDw6695yX+3MqJIuqRILILiFT7\n" +
            "wbETTI4AAQCn8lZVOHSpHB2yOjK8nhQGeVA/U6vZo4Gqh+651VmbFA8dtBhCb2Ig\n" +
            "PGJvYkBwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCY6CMegkQhLi6aAqEgWoWIQQ4\n" +
            "88tVxAl/ABz1XryEuLpoCoSBagKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAAAW\n" +
            "rgEAk6Om3oG2EGac6vmAvSKnLBY6kXluzaQOdDUr4YGZhccA/2GRIzFb7C9B1uQt\n" +
            "D0vkaKqVACznTJuUqtMvHa29yUQItBVCb2IgPGJvYkBleGFtcGxlLm9yZz6IjAQT\n" +
            "FgoAPgUCY6CMegkQhLi6aAqEgWoWIQQ488tVxAl/ABz1XryEuLpoCoSBagKeAQKb\n" +
            "AQUWAgMBAAQLCQgHBRUKCQgLAAA6RAEA718YSn05AlsXm2Z/fudbg5+iJkT8wFmA\n" +
            "GduAFD115ToBAMUOJOK5bcAthjg2U2zqobFcxCV783YM8DmtfR52JzEGtCZCb2Ji\n" +
            "eSAod29yayBlbWFpbCkgPGJvYmJ5QG9wZW5wZ3Aub3JnPoiMBBMWCgA+BQJjoIx6\n" +
            "CRCEuLpoCoSBahYhBDjzy1XECX8AHPVevIS4umgKhIFqAp4BApsBBRYCAwEABAsJ\n" +
            "CAcFFQoJCAsAAAwfAP9eW2jlf4aoqIKVv97dVTOt1epTUKuf4cFXqgU3bbY4YwEA\n" +
            "mBd10WypURuOEBuQqnbm1P4QyfPVwByAR02v64B4ZQucXQRjoIx6EgorBgEEAZdV\n" +
            "AQUBAQdAWTMr3llfiE8g1fcu7eJF2EVfxZHKMWvXSo8gYDkrpnIDAQgHAAD/SfRY\n" +
            "91eeLMWXuAw+1IPm1LYsZaoiLVPNuioMjyqLihAQSYh1BBgWCgAdBQJjoIx6Ap4B\n" +
            "ApsMBRYCAwEABAsJCAcFFQoJCAsACgkQhLi6aAqEgWp8CgD/U9VOqKmlDFaCyONQ\n" +
            "4/G0S48v09aITIAFv+CnFYNLUmEBAPm+ueJS53RHCvHalzE36DpIdqvGlAHd0Qdc\n" +
            "6pBnQIwPnFgEY6CMehYJKwYBBAHaRw8BAQdAlnsBmMTGerPI3PG2ECKvxbaqSmd3\n" +
            "nmM02yPtPEPk5sgAAP4o0kwl/+H9Y/6muWxsfHAzPdV1Y+kzRmCLolWtXKGyIxGq\n" +
            "iNUEGBYKAH0FAmOgjHoCngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJj\n" +
            "oIx6AAoJEJU1ebg5YtNtNpUBAIEvKGt0UigHQXiLTiTPVJV/cvoVoTzSPYQ/QVG0\n" +
            "D0C2AQCn/onM4My7+a+UAnY+BWqkm+9Vqu9IUP3yNdoyf1qdAQAKCRCEuLpoCoSB\n" +
            "amxNAP0bUleYrczm2f5cGoxHmXLvXxG7BvYajiFn1/8ytAmagwD+LzS7bceM6bLv\n" +
            "0t0OcF2+5oAbgljPaq+Lv49ovfTqiwo=\n" +
            "=uqlG\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void generateKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        System.out.println(PGPainless.asciiArmor(PGPainless.buildKeyRing()
                        .addUserId("Bob <bob@pgpainless.org>")
                        .addUserId("Bob <bob@example.org>")
                        .addUserId("Bobby (work email) <bobby@openpgp.org>")
                        .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                        .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                        .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                        .build()));
    }

    @Test
    public void testReplaceSingleUserId() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(ALICE_KEY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        PGPSecretKeyRing modified = PGPainless.modifyKeyRing(secretKeys)
                .overwriteUserIds(Collections.singletonList("Alois <alois@pgpainless.org>"), protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(modified);
        assertEquals("Alois <alois@pgpainless.org>", info.getPrimaryUserId());
        System.out.println(PGPainless.asciiArmor(modified));
    }
}
