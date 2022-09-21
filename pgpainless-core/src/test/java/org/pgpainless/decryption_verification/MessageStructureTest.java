// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MessageStructureTest {

    public static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "=miES\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static PGPSecretKeyRing secretKeys;
    private static PGPPublicKeyRing certificate;

    @BeforeAll
    public static void prepareKey() throws IOException {
        secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        certificate = PGPainless.extractCertificate(secretKeys);
    }

    public OpenPgpMetadata processMessage(String msg, PGPSecretKeyRing key, PGPPublicKeyRing cert)
            throws PGPException, IOException {
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)))
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(key)
                        .addVerificationCert(cert));

        Streams.drain(decryptionStream);
        decryptionStream.close();

        return decryptionStream.getResult();
    }

    @Test
    public void testECS() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ecs, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String ecs = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/aqIb1rlazw63s0beY1mF9oySuEi+g7bPueL/MSPIpVYh\n" +
            "rtdHuOMxvBX933Btb2URQY17dev1PR9Or3jWJIAk0inS4oe93nNdkhLBdsFZ48lh\n" +
            "qiKvlosiivoaduZJPzpuMV3mwThCN60cfvLSM2F6istEuYGY7r6SsMzqNn7zU1kF\n" +
            "QzpQqhL6XGXjAfi/HGc1ZH44icRR945TvEr+7iPUNg/BX0zv2LCOEtn7R85pAzP8\n" +
            "qe3t/TK+7L7H8owkUXR2+gAtmiIYoVA2T9O3tIzZYDeAhTpSYJqr5/rDYaxIgjkF\n" +
            "aPUgtkj/mZd3N/rFi8B5ApusCzq0ENY0lvtE9njmu+BD8xRU/8ChYOCymcQdGD1E\n" +
            "3U14VzSgW4KQB6AEOSM4p1Ao2TovTe/GKI+4BYKaxHimug4O66VqycoqKuMioLg8\n" +
            "f6uOaaDHkFu2SY5ulrL/AqwYnowCOsiUUJ6T5zd9Wzz1jwf/Kt9WNu11NVBf5bxO\n" +
            "jmLt1W9mLeSZuK/iqFHj0sGkAVZcvtlHiNe+BUfpN3f8qgPMbjRoay9HOkk8/UQQ\n" +
            "0poWVAfk9j65caR4m5Y0EZr7HWtoh6S/Rxg7MgKFDvNC9N3cdyjq57eGn41Y2bre\n" +
            "iGoFzZNTY5RWDsX4iiZD/2dYx8xctI4mprlZ0D4ElckLkHDgadNilRx0OO4NhfF7\n" +
            "zbi624oHaoKxcRG3zPRjkJTjWx8evWdwun0gQ0A1hUAhCAzNjyfi8889u6N8j7+s\n" +
            "bfeH75PKhb0AmTDYq+IOO9GFVWiqqSyTuriqKi0gmkLY9ZHiIpdHulb/JkEFORmJ\n" +
            "gTzJKDVfHge8UboXO7ME0IcZeSnBVBya/FnYMir5gqvIDdIySffRYGQPntp7JDMQ\n" +
            "quZe2uK6QeqIoj5KuxOe03eg4TV69ZFfnSLUfJD7sFnT/1PlWDbxpozOKCkbf7uN\n" +
            "kR/RzOfLMNC28KW7pZHsp9e8xXAID1Kco42wWnLFa68X/krwO6vOH/JtJDNDniUl\n" +
            "9Q4b9/WocEW2DaX28zv4JJfXzz+EViMp8i/nt/+vSrWovzSj3kbKewcv4LwuDSPq\n" +
            "I6RC5eVgckHx2//z8MH5+4IAITn/YJb4rREtFrHvHKdy/lOFy2dU+Ya5rXyCTm4C\n" +
            "jhl65Fclmzg21+oaf8wZ2gtz+X4BmVvaTekap9TrzcyhRPIAlRc/REetd95A6biQ\n" +
            "8ACoSDFXMe8obVE6dZb96Vo0sIjf4j9ZNFDD7h4/KRF11XiXvR6waTUKvkWDC5wC\n" +
            "SYPEdsFlR5hywdBG5SWlL1XmtJVX7aj9Qylp8F5tsGlvXvhak3YLo2gzS4ykH0E5\n" +
            "2XW0s3Lj\n" +
            "=aDBB\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testESC() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(esc, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String esc = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQwAlA6qvbMWzctnJ7kOHNT3Sr+2kSb9VJYhFpKy10ZTtopU\n" +
            "FlGW3sn1t84G2E/Dx+4/jJY9dkUrkV30Z130Pk6lol0GGGc2KA8BYRYm1Cm/+CZm\n" +
            "TdGs2q9LJ9qp+k0jVLTl6AuFL5/s1tVhHDN1uQ/vSy5F3VfVE92cDshPm/xDvXlf\n" +
            "nqxBIGjg/AwA+nVwlyq08OKXRujkPI0CRgHy8om7DuAa3bkjoVDW1UQzNRLk1rMn\n" +
            "YhBmu/mQ45P0rsa9wgVQnYJ9obh2iWm8UzVAVR9uPlqPwjewiII8N7YWEvaiLwcs\n" +
            "utVlgbf88lCf0VXdLuHfvFg3mcJ4WEbgHOSibsdXOsTKTqT0SnQm5rC5dF+1yD/Y\n" +
            "jHdpK/h7o/fJsrPCrQnQVP7KfVAnoSikzlYFZT7zt1xTmkQ2skxT46JRFMaT4Wpi\n" +
            "cG1yoTFbMjKfS0czob1XN+zZZZwxWIV0/1mEX7uKR/s40MjjHppPFSyhtmzlD7fS\n" +
            "D2mHwW53flfORSpc+OBI0sGaAYSByXLs3Mz7QVdj3aLeGN1R0bQEpt6vDgFnnBLn\n" +
            "DKcK/E9K9K386qjHRSGC+w9UhhXUExLuiWM0Tk/59HJbBSweYOjlfTMoLI7CyWYZ\n" +
            "CDcPKTJ3Z7l8g3KRlIPoiuuTLLM+tZ+OCwkiszf+rskOGs407EdrwOnnAOgUf6ht\n" +
            "jghzFjIERQIGNuO7IcaM8rgjT771dNaUtMbHx0BjDniG8v4AbeA4NGL5xTMxy3sP\n" +
            "SOzwrQlBVzOFMzVfHgWw9zOYIWYEidqMjCcq2enLApoyUpenPmunaW8i3Kq8/CPK\n" +
            "+HVtRtGlNVnX+tsAuV1V0d0TU8iqdQP/SEJ0Rhj82ubYYnUuTo38bWqgM3F8EBpd\n" +
            "AnNsT0q97e8VKlZyl3htxUy6g3nZMXR1PPoDwPe01uRnjNuNPZVIZyMMTP0N/9BJ\n" +
            "9XvLDEBYpqMa7hp9VoB+gO+MP6Iz/4bIHv/m51E813VGxMtkS/1eej0lyL8lXtH6\n" +
            "XwcyX/rjjZ8hE9NkrnRP30dnAzVIWvU8jF0SDM2G2dMJwDmoie4wwJmT90Cm0af1\n" +
            "tLEnXY0d6ntm6sLwIPs+QJrDVUNzxxPUQ4bQ4C3nQ5v97eRN/QpnBn8PaRHxPmPz\n" +
            "IdbWFQgFpb2yLUyfYj2DUhbFhif0ZfU/11pHSBmiSvzKFAAMPqBrdR2bJ6mVyPpE\n" +
            "BU4v/ao6Yp1yL/9nNn20Nn8qOw60RSrC5Ty3KbWtUsjiyzBNA8IlCPJDsKo51//b\n" +
            "cnvZjNPYRJOchAHq11aA++gjnyHfH/ZR3TFTymglxFog/qagUtH7DHUnpeM=\n" +
            "=5Ego\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testCES() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ces, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String ces = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "yMMzAQHtAxL8wcDMA3wvqk35PDeyAQwAs8bUPPzclPWDHc4njvJk6JoKAPAzKV6C\n" +
            "Xe77hfIlhmW4WW/j9PdNwuoVesqoFSBHOpgJ5VIlxX0fIzD3lKj9NcVTTvrEXrIe\n" +
            "fp+5sjzCpWXu48df4RZE8HHnAu1XHT/sKRy+ospeJkx1l7Jh3ioNfJFMiA8oyydz\n" +
            "AWAJZUAzGDXiIemKuE0qmZgDIFqNSKBEgc2a9a9NlukP7AAt8Ff49XJ7XknTfxEz\n" +
            "bpufsXbwocrMwcV6/uj+Yq1sEPaC/ytUMtKmrkWetfVHQt5p8u4xTsQ7uuc1yXWy\n" +
            "eGC/SvhF0it4e0AQAp8GgzJA/n1BPJMMMp+myMKkpHlrbvLVoYxRagkHW7JkX41G\n" +
            "TLkb6tUM4l1N5s57WbiW9/8wi2sPh9Ra2J47KgWrBWFf0Q+TTphs3arPaN3yrAcT\n" +
            "gLOp1Pq64IsXU/9tmRkKY37S06y4xwTrGQ0Uu/LK6sSRhCvOEsf8BfbkXuRQDoDI\n" +
            "Dy1E27r1UhkVUycGOmgBodEmeB6I2nyH0sGbAagMLgknKRp5fi+eySa8cI3ehlFo\n" +
            "QkxpZX2wWhHECJZfu7k+OJH+LX8FKrmBhVElTdLg5qIto2PPTY2IBr5psIrSRQY6\n" +
            "a35K604zcwTpP1hY2YbMSNRhfKud9g8oi40p5SoNtS1P8Kn5yp3QkIu5Rbnz77u5\n" +
            "QiVjE7SfU0cFrH0GwxEDstJyJB+2Vgv32xYPgmhBmfegtnvP7qT8zljN34DYuILs\n" +
            "QOxUiNgam9R7ooBR3ek5kOBLZCJN7oSO26ci437Gj/+HgjLmV2nK4rpE1XZnY//k\n" +
            "gLkzjg48Fq3Rm36rgHp6Hxmwejz/Q5tOawOtIsz+xRjQVKNt7EpBQQGUKehbDUQ+\n" +
            "VJsf0Y4IFEbDNAUCOnTFb1KUidNFeIOhGVzdmgCWEV6VFEqJ9UhCKhKALohXiU+0\n" +
            "tc1xMaC+ijyOXenMQtBwJVGvh8g+vBhEoioI+kqUf1IYGOLnMGVK2qEWnk0GtSbb\n" +
            "1fqDN0gJSwVR3oWyH/S/AZg/itTZ5SC/2ztznv1RLGKo5pgWwS+MIASvo5dRIhka\n" +
            "ZGe9/gRJsahGSuL1/49XHwmfulfM+3kSfXECwo7+7L9gs88wN5Mw0OIu2d8/P/8L\n" +
            "pkbBSFily3i27ChyY0h/jBnGDNWMidYl4IwNV2YGB97ga8HyAlJufCyNwqU7ci4C\n" +
            "15W/JmDuBYPBCQ+aABsABhtPXWhUan8uvhQH4FVVElZ2+9NpW7B0AUAnXVZMYBEn\n" +
            "inXQdIKQM6toFYE+CmGQOj4ZwiaiIYKgf7SF1B0Y4Y72Ne7TGUlYlkjuF0v3Pf1y\n" +
            "JcEQljRY\n" +
            "=xtwh\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testCSE() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(cse, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String cse = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "yMMyAQHsAxP8xA0DAAoB+/zIKgFeczABwcDMA3wvqk35PDeyAQv+IoWprhZIA8kB\n" +
            "rUP3Ca4yD4c7dlPAlstv7L3atENjZudbppL33Vh9Udx3M2yy6CfsRee+dYsfErWq\n" +
            "xqol3H4N149uo0LBlfZwyvzSJPrOEjksyMxUe9zRdEIHtzCkeSuioRvYZzqM4xYS\n" +
            "/tHYXsRu3N6XTh69K5ETyBpdSvFphAV/pGCkU6btFDTopyG62MnDebwhFN3SwE8I\n" +
            "YyNJiEMpxG7LCvj5wcxhlba3h/ToDXbz7YYnyRw1rllHC952cbCt2u8kfbtwlr65\n" +
            "izEfCuCcELJYT48wMs11raEQYpfJNBSfif60aKjc3DSxGs7X9HoNNzzqz10mcpK+\n" +
            "XDS+VuOJmHRKYmN1Ay/yH9jIzvucx5Ug+hT5oN+LQGxi4dZPLGfrsf/YABnoi11R\n" +
            "fyrTjx9D2Q225SfFhin9AigUnT5Mmsx2es5XgITtQzqt+uqUCKnYuPmpDGibymRu\n" +
            "fRrQCAe2St6vhv33SPKI1n9mQ76GeNfjyhttOgWPVZql3mcPvfMR0k4BRMcqpqxU\n" +
            "6vORRN80eLxTxiVIpXevOI3WBW1X7LxmnMJprBdhi2pIGrfPDoE79TghyQTDOeC3\n" +
            "icps4qEBvS5YEDZLs03czL0ABXh5QxvCwTsEAAEKAG8FgmMrBwUJEPv8yCoBXnMw\n" +
            "RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZzbYbU3OOpKv\n" +
            "qxWxxKIvX0/87eH+r+ysdeBIzhBQJLM+FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAA\n" +
            "AMv+C/9P9aBP0edUhXY3he0EeHh2nGRDiErrC2d+wx7t1UXL3bs87PoOzygj5zJg\n" +
            "+DD1XG022lxY7ywMFotrab02lumEDl2LSo5ii1qXVBCghzEBPzasDbkQQBew33kq\n" +
            "3mf8WtQazIaI2wzjkJNUhGPmJiA47mlGxeS73NGAYZHELU5DjRlGQ3UwDIn7UYHG\n" +
            "Q4eIgOnttFEmNPciJ1n4p26ox1HV10p+s0Foc8DmNoINzuWErB9aac/5QuEHddDo\n" +
            "RzS+u0XpNA2t30Bn6G1K7WOn8Hstcx+v9mo1FfJvviYmAXTx6PdkozmJCsg5XAnC\n" +
            "yxwP2pKHjMNl4jVcGtCxVUAbAYkdyCwwJqm13LXMiscJv1C6hPaLgoOwgAGzAWqu\n" +
            "vcckJjLuItJV/0On/76xsKIQKasz/pfxo4N53trE+P1f/SjJ0EYjoWzJZz+3Zi3m\n" +
            "QJ94Pdd+3AtmfGWVSwu59NJ8Twgf8VSP8OiOaEeLheAHPMTbf5Jzfc7UkhCx/jQt\n" +
            "5JpkklM=\n" +
            "=3zkk\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testSEC() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(sec, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String sec = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "xA0DAAoB+/zIKgFeczABwcDMA3wvqk35PDeyAQwAsPqIWFn69346rkmNsY+O/P/Q\n" +
            "tvAYsIbOsILyiCOj/fWCqwE3DukQsoV89jHtQI/iNSpU4V1dNNLYNAerEMkoBQa3\n" +
            "BT45ltwDOkpeLSluiBqoitjb0AdSpr6+9h/pphmBewZkJgNz7j+/9hDXNqxisLhr\n" +
            "5zPgo0HtDX4xJBeW0D/AQSIFxL8lFf7gUDcN/Q5S+r9i8NKE79P8Ilust7OM8NnV\n" +
            "1P323gl+Qvs4uiwWTYG/VL41uE1n4Vc8pmqJpeJZT7CXBl2p4NeW8Ovrng27/6HM\n" +
            "LGK2jVn0MjAjAQiTDPaCf/C59FX8yIwjdnJcHBv+MAwsM9wws+N2ZU61ewBfXhhX\n" +
            "wwKIyAOto7Hy/TmrPjutGrJaoufH5iACUPo1qpW9Bo07B5aSeoUeVCv8XsQSroI8\n" +
            "exVmyPOHshaiF3TTx6ldfwjF6HHO6IWcncQ1O/eIU3hPT8THMWEQZFdxISH+L/61\n" +
            "JlD4POFdrLkmUfrbRerVV6PrBqkmfjVHqy1LhfMh0k0B+4+OQEAy33iC7I2mRoNF\n" +
            "Ww8e6+lyZtTINFqWeMCKwkZ42NxUwtqyKSXIPZqfAWLILzhUyQJ66sq1990+VPPK\n" +
            "Ec/d7waoDqX2n2tq+8LBOwQAAQoAbwWCYysHBQkQ+/zIKgFeczBHFAAAAAAAHgAg\n" +
            "c2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnRy92WQVB1lfZ6ed8LMypLdLp\n" +
            "3YNcCh1yKQJ2fY80cdIWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAf+EMAJzflg71\n" +
            "aA6zSMZeMkncWg612ckpJ4Y5mwYLqU83rXGn5V6qjj78sKwKUjEV1nQgLDdRLzDU\n" +
            "PUIHD3WDuVpfcXCyOBxXSM5e5iWq4MAfU8tvMvMuOeWQ5Pziw5nm7j2kwtcsdUS+\n" +
            "zlU6QyVc5dnRMuHpA9j4QdrP6L0kUxj3CZMwoLvjwm2E566HRo/5XHjCWSCuWPXN\n" +
            "BAAEnOvAZI85qpX9eIxWp1e/652jHCDY0SGzYwjD0dxu+XbzexO4O3T+7+YRjWkK\n" +
            "CzdtvWcmtFcBky5GHWt2QcLi8506dilgBUMK9ZTD+46dZQmE7V2WBbYuVZqoNWCU\n" +
            "I2cV4rez4PGf3CfypqxifzYHebwq1XzkyH0YCAzq9+be+QaOGoWx7HWjRLoip6vX\n" +
            "3qx0QYeQZsKyy57VQ3Y52dUA6S3ZE+xU+cZ2TcqRTrd+2ILbJFwarxmTxKz/ZZSt\n" +
            "kQ5VSwggSnTQMU4l0bUfEm9/x3EW4uiJgf3SyCAAABMcdTCXvlkuE8Eilg==\n" +
            "=1Y3Z\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testSCE() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(sce, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String sce = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "xA0DAAoB+/zIKgFeczAByMElAQHfASD+wcDMA3wvqk35PDeyAQwAlg4+VrS/1eWq\n" +
            "rwOPYgVDV1mczlDBQ0A6PRkmzr2Yr+bI97OmoJKfeeORaDiC/pMrfcCDvp6AW268\n" +
            "+pE7NPp0Gudl1q/NyT7MLM+DHy2EfmyrEsYfqfUPRnzUAPfh0DJfn0eS0nAtXn84\n" +
            "8Tk3f4C2LBuI5pdDWEie/zlxZhmPT/s6SEbfEHsjBBk/7llmrh5227+8cgkYFoyH\n" +
            "f/nq7UYK+EcaClYwgat49XGx+KOhXHqcvPO/iqqkRR7XkwW7S3QjgDOVrqgMw+mC\n" +
            "3FB1vaSDL8iKQ+PMZr0pSetmxysKmRPl3HqSsDHtz0d7ckh6pWzrXD9AVW7rE0Ob\n" +
            "cST+ek87dk3TZ9NLpKF0mejiPd7Dc7/f9ti8mA2qum79iJXU7WiCCL0Ng98wqFk5\n" +
            "SDEg0BaN0E905sFS1E6OGnHTcLVue36H0Mf767hLFc2ea1BBEF0VzhrETA6haWM6\n" +
            "OpiYpIqy1KYfbVNW48CRIxKt4F26zHIWqBvyagNPlv3SgXd4fCT80k4BwRbYjoyk\n" +
            "tfV/yPXt8UrJRSBf/u1uMXH9a0qHzm8c05SfVYu2xIt/oRkckDN7m+M3W6b7c/+j\n" +
            "AHftfHlpstZ9zrr4Hz3iXei561GtD57CwTsEAAEKAG8FgmMrBwUJEPv8yCoBXnMw\n" +
            "RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/FbVVk8pfJG\n" +
            "QJ4aTlS591W4NtS12e7Ff+FXt3pxktSiFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAA\n" +
            "AL+JC/0bxg4AMDAkh+LB8IQkQcrCo/DgqQ0kxW/qJafhN4u2e8d7iWe9MKWs38GA\n" +
            "6ELl8vKRVNJvXw60nRaPpkFlqH3Ph+s8uAGw9dOoT9Ts2jwWPdbCg1jyGgc27Z6F\n" +
            "fw0nTpRHHAadQ9aRb1yb1Kp78j1W4wUmYq71UWi85ea/qvHuGaptxt7AMl1NehQT\n" +
            "hkxsXTKtv4Lk44DaSZhQ9BgOjVUWhiE3kM5vimcCEtH3oPxIQOEaP+FLpQb4bbbz\n" +
            "viJZMUYxQsw2m/1Exh8tHLG0RNqfZ2WMGp2qLzgFC1JJ+66WdkM+3LpJi8aPYRJS\n" +
            "v2EXnqw7NeDKOLjVWA/vqPHmiyxQgzS51dvgkciZC49kJdmIZMoR7Bl6VFFTmj0L\n" +
            "/+kc6nRdNpMUHwkhg+aUZQOIz4dXAoebMlI8A4ePx4PcwZh6vP/hP8VJqY4noAJG\n" +
            "0AuveI9KTPT4ceqfJ20v4vFq/y8nT0h/6NWErc8qiU/EUDP4q2dbX//x5WsxfcHJ\n" +
            "iPhrBgw=\n" +
            "=Z1Ii\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testEES() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ees, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String ees = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQwAh7gbpMBDEsGnu6rSB04qI30Ix+cf1QhbSR4aiXOp89j4\n" +
            "WMIrm1imewJL+b/LhZsruS3kzeqH0aRSQYmFnfuW28marsp+Td+R+zXgld3mgxde\n" +
            "JQfX4rrMC8G6if8ad5og/InltFyjhMX1MyE6uu1U/4/8rAyU/3J1sa6POlSIIeut\n" +
            "h/zLYdLHP9I2yoyeJoOSRxh9t73ByePYwwUxOTPxkLIdkRvkAMHi9ooFe2OZBIzc\n" +
            "ZjgJ0nZNdxr/Wf5jEwUfLS1ZEFDfjxvnXMeGfQsDO4McAVtYjutGJuf5GWjWGcz1\n" +
            "+Dy2EhObvi9LoHi71qNVojBs+IHWMTMFXUGrmqeyG14/YsCyY57vvQgzo5kMFXfI\n" +
            "9PvrBQvxWFzp7pA6xqywzDJBoZGLIQDH5b/0lpRzsDE3DoY10VfX9nKlfBt5PZ+G\n" +
            "vZGAiHEZp5C5naVwKaQ4fJsMPUFHOhPvEQJqP+Xwn7iMZ1+obV11Px1ZODB+vfN9\n" +
            "kS1K5HhdS2EzhR9cgqVy0sNVAaPRvM5pCMeBjvDP9NZnwUlF5XJoPFpr73ZgwlY+\n" +
            "9uf6lEu7Xk+2GegZOPoxPU6QMPOonMNPD6Is277unIKIfzb0vs91zfRi62ysnIlz\n" +
            "tnsAKmI2lOgv0KhPNSFFTOycjYzvirvIhQYtEZ412rrykpEwLhF8HG4/AbzbD8xb\n" +
            "0UJjAi1/hAZxWaNfEjk+WthQocrHrVAnNcULmIUhyvV5b6sbr0r/qCPd5Sz/K4Qs\n" +
            "R87Ct/C2IogerMnc0LF1MrGimyAFtN91L6zUFgU+eWe8mt5TbExnHnNMEAJpDwWy\n" +
            "3gimzkC6QwhePX1BU2ipN4Q/8DMdwS9gtFerWOLLqMNBcVChWuk9ArdicDbfFDyp\n" +
            "7s2joDNHTuLTYn+J4xZASruFeMNkdLPFFRcg6Dd3wTNy/ss4CZFOzx5sK8WdVzr6\n" +
            "G3FaQhmeWzUGFC2YvCq8/tu36PtNGnB4Neaa1NnHXCxpxVRwECQUfZ/HxwvqfgXa\n" +
            "8ZiF/npk0z7xed204D9F17fpCamO3aWCd3u73zvQCf/6ylB6dDU8q8mOWip+/9YL\n" +
            "iwZRr1JNzVyoRDRmhQUeaId4LTbWwSTZ+gUjGAo6b5Qplha7gAZR9wr4fsZmr57V\n" +
            "G3rWgyng6Fbj+KR/XOCO04lDSCV2E3uBQYspP2u7e8YI5ARvy1AEH3eGwFcQWbOe\n" +
            "vHxPnAu4kPWeZu94TphsGzs5p3rSqAtzumGkyswkPOFAXto4uHtEKyeWBfpRi1J7\n" +
            "j26FhcNePE0o5c2Kp74rJfDROkpxFXM/kwv4GJCv2IZebUIPItFpWysUn6FC0w0I\n" +
            "Yh91Ati85NsOKq3k/nqCtMlW1ZuKwJLOyJRWXruGI8BjacvEsD5FiTHZbIZwBpV2\n" +
            "4Y5IUtX7uzZakSIb155xNEWxdyg7vevYdKvOaJVie8W4bMBObaC0d+TYy5Wbugav\n" +
            "/OHZaAbHYVU9g2zp9HP8v/06kQROKEvHPZVSUCVIz7PUGpOo1PH67oJ9kYXOlxdU\n" +
            "zO2SKuvtvUlQctQCk3nclfQBmFnxvJYonoOf4ggSdjSYheZBcxXBBoRHdtAe4jPD\n" +
            "EQrHH5670gaClvhPquZVtdZ1Xqf8zmZAyAb7/Y11oxXgZQHJHOJd0Fp4RSLBgol2\n" +
            "zsGay7o85rRRhcvdozUavUixNCqFi8+E3udY25jrI6xvVJUAajOqc16+RexFsHDK\n" +
            "0H8comaMmh2sH39TB4U+rWiKX1PYCQ7nLaKdL4MjKcvTEE1Ous9q/ihq5J/mQBS2\n" +
            "N9fEk5HB5OVNDtaSveLCKdZa2R9899kJB1kVDVNAAZ1szGLTdkWM6WeEBngO7eYa\n" +
            "2fFOJfn1JD1QRx6i/n5+DZYqbteKLieqLg8cQ9CwNv6dHoUs1HiX04fauB3u3Kkj\n" +
            "tEO01lzKcA==\n" +
            "=YGYp\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testESE() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ese, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String ese = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+Ka1lKg4enHS6QD31mvJEiG7UG4Baaq5w/g4qp/GZjHoe\n" +
            "63RHReIrv1AlmO7oDJ2vaISl2tKtpCMGvzkbHcjLtVijXzAL42DkfAn+hOQmqIXE\n" +
            "RawUaYOlWFbUall1lvgGXG7Gn3mcqjVqI1lK2kZM07Vy0wf9dddH+DFOA7Q/KSsK\n" +
            "bGdq7G+m1OEf5ZUeGuqy1+qNJFvdrxISGSLc2OM2JLJDGQYrwNNgwB293IcFhHha\n" +
            "Z3pcYANok2T318BXWhOOymmzzbuw70pckqXfzPZ3ULIzXAJRpQbbQJy4cmGZRrCA\n" +
            "7wEMBZY7PbUMRj6ur+OFJFzmQJ4SLNrGofYlU3KV7UYEdB00leXCqlu0o8qFbvkn\n" +
            "eUlyi2R5MSF/JlKb2xMGGlHZDmPWz88ehLrFmXjPvhF5wk3tbGLU11yFCg7HLZ1J\n" +
            "Nlo5B8PmdE478aVqdaxYK+2BeQErxzvzRNV4hVwz1LRccBDl5WEVR9ArkwcnkPbA\n" +
            "aIHnsV6Shi8xMSwdQDJk0sNUAR74PHePZ2/5moqwBbXw5vyW2KLvY1f7EJudQCPj\n" +
            "suF4xpNXJNiQc6WXD4deJOBcbc/gRSGpY2QgeyKEM/d8pzcVlJoP3TVuW7d3tMRe\n" +
            "1WxrlYIJYUGWHO2nkD8GaAchbRuvAw8hXr0TUxbNrUEY4Gx0j5lwB0hOFyIRrS5Z\n" +
            "sJmja2JSXgHwOJ1lng9UFOcVDBkflg9ClZ8PicBA/Dqd3WH/cFYHaAencLHjsiKs\n" +
            "SBw6EU5JduiLUHSj6++dv4O3HSfTQr49cwFYhoSxvQrNyl2f76Vy+37NL3b10tHF\n" +
            "Rev85MS22S4iuljDeudTqcrJOwqqDhL6Ue8P8HdvXJ716jofzJU2L9dCDbt+wvQT\n" +
            "khru3imP14+c15IZTbo4AfBkXtmQmXkc+T5rvbwOHeTZufoXDPk5fh42dy6N1yje\n" +
            "0xuHnEAb4yYDoliJqYqDjdpq3fi588t6KsguhgluIzlMPkSilV8CR3uquEsqDvef\n" +
            "r3XhTi/qZWbjJZkBzCqXFzGrp12mNbmb5LKYucVDsmaF6wAlT0cCoazNCzNRxVpG\n" +
            "SMBLnVr1c4vIyZi2oHrMnBlqTP284AFhTIKWJpnqKJcwU69hTNie7eiD9IhLP6SU\n" +
            "KY9sC+mKRz81iBKIUKvuM9PwQ5d1tdGP2sTV/5hq9dnuWmfqCxqmp4W+jj7igESb\n" +
            "S8UYJ4DuVw2p+Hu1sCwrnahyATa6pmdGxg6OpAe/5VHxbPrW2ksZZGv+dWFpb2L6\n" +
            "8SPfaSKEarwaD5JmK66kZ3yDA8CUinwhYi0pAMaR1P/+rt8nXndpQx1kd94QEfHl\n" +
            "6rxMXfrbXoVSm9CV0FdpZokRhcCnv/F9nx1+JR07wxtPkHw9z4r8SPYVF1rboeIJ\n" +
            "A2JnebkSgt0HIu7fL0/ftd4d8p2fp2gbeZhz8YEuz+C4LgbYvDjdyCE0Y1gGuXUu\n" +
            "0vwcbjNuk5k3ubcV9/+YFBuwkzg+XLYy10lJ4klbYkOolkgXFPmMtaIMA71R3Rd6\n" +
            "IWbvSk+6A426nJs6xvIo2cVHk/oDzaUuuvxiPdyCfy+WzxArN0+6GOBHHDfa0266\n" +
            "OCgAB6SpXBe92THqiW+XI/RMCbH/rvw78CGVyyb2fqd+zlMKVtZ54PHn+1hAFmVI\n" +
            "Ar4kI5VouhmsInHWMduJoHM4Rk8QeptKT37vf6KAYO+5CIO0GCPkwwJQG4x406wf\n" +
            "6SH0Kg0eBgOvqC5Jf9i4aBx4wKx1NryooqfANktSPBi1kShkl72iRB3Z/JIctNai\n" +
            "UQJnmm4V5ZYeK5F/mrdIFwcQB5kJv0BszmqiUTV2gmVnD++dSVbb2Yoo6lTjXj/u\n" +
            "J0xRzD5EUwmAWqLAU/nT1xWVv9R3Q8J9WqvN91EgDb1FemX23f4Fp6a71ui/TYab\n" +
            "que9IQ4E\n" +
            "=gtwa\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testSES() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ses, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String ses = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "xA0DAAoB+/zIKgFeczABwcDMA3wvqk35PDeyAQv/a6YILQafFCOXoJaXkN1nMM1I\n" +
            "AHKpXV82DTvE6UdgwF7dbur5EyzJKvxLR+vS8tgVfr/8H7U59tygftiibFRDRvaa\n" +
            "uguSfnTmoJpXjljPvHRYTrrJqakWGchEKrUePnwFYzb9Axy821Er2JnW6VIBTau7\n" +
            "OuNdSQMu8y41Fp/9VNoxv2yx94ozGt3Ya9yaAzcksTC3c/rFfVTlHlJJM0QdwpYU\n" +
            "DTX5tBwTNDOzgY30nb/1AH1Bt6ZAX1MVHe2sX0cBMw69CH9kRoWuMdGa/jLkXfLG\n" +
            "Bgp2ieLQ+j3KlTc5fnqlfwxUbw5pL76zM1HaN1xYNh8P+aGy2PUu9803m6zrHZiE\n" +
            "Utd/mb5z5btMvAnqQlMEwUVr+garymFQC2OBN1cpC119TkGxyi28Pw6Ob/xoXc7n\n" +
            "VNpI93sbXi1PBOaupZoWH9gE5J0BWtbZ1P9QiCB1D2/scOCJGKJxVIInGLWSONpj\n" +
            "BjJK6ngyb3qIpPrfN1TPcwpeMsS3Gv0zHYQSpCXv0sGXASezMfAZ4RKBRw+6yo0o\n" +
            "Rht7D5lBzH273OgFSxKckwJclvxwIjrYtqmFsKygWBbl+B4PJ8JmU6jggzvpkvoI\n" +
            "Of3C2my/JaKkirIsV5jnD9iXBaftoMI680nRa2JrV+LaF7GiS3gqRwpNNjcOXMhz\n" +
            "kUazWUQML5OQWomJ8BkLc0Z8rf20psO88pW2+Iil6xr58lWo1JCuPNWf0aA4XqtC\n" +
            "UlUj71o09s03ofB/ouslo0ixmw8+ZfVt3zNj196BZfXwJcbixBBM3Xi86VoS/a+z\n" +
            "aN8Ebd2BtS9M4Kb3w4RNSCIWDmXSDvJ8Nx8FYS4qvyenB0iLc5GpO6MHj3ebJrZ9\n" +
            "MXr5vd6siAO4Ie0cZfX9uYA23HpBCbelRDg/57LiWffm/DLpvidUvexY4DXX/GKE\n" +
            "Z9TddHh5geQFGd9GpKEwTNs6lwWjwP7bX6xYDGuwWE2v4oERwqC/ZJMrisToamwt\n" +
            "2lgHu2qvxw7SyhcedzjSiwq3YkTgl/vXgg9G0QPaz6OO4G906biczx4bY9JkkF/9\n" +
            "HQAKhO9zZLxWYv3uZKE+lqnuXbpZCC3sUd/pyMvK62F0S7E48GzAvDWqNS4p1r2l\n" +
            "6k3Vw0CW/Qhf7osR2xqRQKlSQZV1M+c3M8TJmSgIJY3HjCtVeWXKszsR1kVdPSKu\n" +
            "7Qx72THrSYRDRRqhUUXEvs8O2rMh8HXt9sKXwhd8Vjx7TdWpnxhnqg+rpBQWbpO5\n" +
            "0lXYjjgBp+Vx50ojeF0jRfohoWw0CC6mAJOPRwDzgZQFb1/Y/l2lKxtG8IwLYXKX\n" +
            "S/Dwt8w2tlfCwTsEAAEKAG8FgmMrBwUJEPv8yCoBXnMwRxQAAAAAAB4AIHNhbHRA\n" +
            "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ5o1WOIAJ+mS3PiiSiMpSn86PytGVoVv\n" +
            "3JsXiBD3DXugFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAP7tDACiOPFNGYC7e4XS\n" +
            "kPG4W8IhSKSFtqmAXCuCe6oGSGAffVg4LWEQ3BxW5px0qvDEo5MHwBU6JUeV/AcB\n" +
            "zRl5B6wmqCIman2C55/G3n9EyjTmGaWggQKOTSnwJNfhYHE+djSxBaEVEjxMzjDF\n" +
            "S3BrI0xNiOczCUuiCABbsXFiy3BHgKVlAqa/IGQO55bnKEt4AvdmEIcwpfKYV0aZ\n" +
            "CHKfW53c2C3hEBumM7c9UV2dyoTuY763mWuXT8j+DE9/Mh5LyMZ0ac1YR9zY0Ejy\n" +
            "5H/Zthq94UNezcKMmfcHvT2Yr4CSy/006VD4h1xiMkLidMI5HJjzlHrfFnYio5Pf\n" +
            "uw983vj0XANoGJ5Z2wV/MRoTDm4OELX0zjph+mUffbr0wZ/eAbfChiS1zaPHk+h9\n" +
            "+PfV7v40QzFFUH8cIwCZ8gU6GQtIC18hKpDRzFn7cmaLs5vkUECxSI+np6PbNk77\n" +
            "IVUiSDqqg5VN9uNgoKxn9UrjhnI2Sk/r2wUXjK2raJfaZBLA0SA=\n" +
            "=UWHO\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testECC() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ecc, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertFalse(metadata.isVerified());
    }

    public static final String ecc = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/XrT1vHWgyT82/nZ5Lb3MAaUqjAnfr+n34t+v0bBXSozv\n" +
            "sifZlAR7qIWpsssGiYV5ObMlnLLk+30vFJEiux/fC9n2WmGkBiEgpUTA5VrK4VcI\n" +
            "/UAQKeCsviNSAAUKJrQ3KKKhSYXAFYIwXUHilDIx9S1Df/w3yY/AU+3pzSg/V+tQ\n" +
            "ur/8fAjL8IxNWhLJquZUpVHLm8we8pEOI5Z+UhtqCHH7wsawW/+o9B/m0A0TODhT\n" +
            "hS9ZnZgVbi8L9tpsYFqar5bXkLfIb4a4vtA9Zs0tF/nUmx+lB1Jj6yI81ols50aX\n" +
            "iXAYIqEr8Y0dgmxNX2bcbZCZ8lwK4qgjxqO6QbkTTvjvHEByBiIyPrs24O11GuHQ\n" +
            "QFrY/ibd/OeJVREFivxr79qHeiASvRdUMCBEX24FlfVY28DUal0ovQAhXOwSprxk\n" +
            "CL7MSPvT86n8ZZ9TV4BOu+ORdNMM40LwhPgmubFUvA6xWNk09Vykzv+O6YDfNcta\n" +
            "DhBdlnZs6XtADkbDBshp0k8B0QmgY0262pTXaVn5JBsDHbpij0wWIADX+mKeIowK\n" +
            "Wl0OIY+Xo9Jh1bUHcCpM64+ijpw0EuweNyntGdQ96z0EmpgWi7H8G4Yux8o5RbFo\n" +
            "=JL56\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testESS() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(ess, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String ess = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQwAgueK2ynRsCYYAvWoJSuPLuMxC6ALUI3BhWh/joGBeI9C\n" +
            "OZNC2Afnn2CWLZvo6j9ivbXX9UPnj/PFdwieik5b+coHimgpaJOfezcY6wLl31vR\n" +
            "HBBaUtKL0DiKRnkLNY37xmwBujEkaCmWSgTHQAYcDsGdtmUeLgjcAwAOpzNNLo+O\n" +
            "5zGVd7H9KuYxJZL1Q2dx10A+2uGjwXMdauBkp94ojY5Ho7dAHNeI6laYMdwBUbmT\n" +
            "kLov9nFUfLytNDarNdGiiikUaolUuHFd+YSNN2N033a9MLAKSZs1fP2j3J+bo5tV\n" +
            "hx2jVKuQAoWz5xD4sjMm5//nSW5kVAEvwPiAlTZsryLJraDvUm7JPjLiAnecjNcH\n" +
            "CvfmqyDSFbsaQ9Plb2/aHMLJ1h6CE890y1EFfKKB5I/G8QBSrx/tEj+f+DKZ8ItS\n" +
            "FTtudeC25UK/lIBxjf5shmL1wSX3bca7byxIIBWiM0M7mH7dIxiChYDvBL/YqbUu\n" +
            "oRDvnf8Dhc7TuLrS1o1Y0sOkAcF8fHDLCmEhmmKSuvAhS82kff6Cc7Hy9BSPwxCc\n" +
            "WRKRWcU3FZFrSVvwsJEUs+ICTIp0O+fo4dj75m/nO/olMrOp0C4732goXt6//6xT\n" +
            "TceiwZucYdLeohWyWUff807p4p2Z+PJIDOb6p2cCk9RCDJzMMayOvIWUzK/u2Hzw\n" +
            "jw4lRD4DhBWimfYnZImgfISV3wu7lHSwqiPCCPAPjT5vBGF8e4v8j60bWZs+Zl+/\n" +
            "csKt0FVkbVRlVHrSf6onoeNG4fpZWRLL8hunvot4aF44UpDhF0gNfm6iYG8IAaOx\n" +
            "ns1hqpdHNUYxgaJ8S2b0YjigCh8eSwJYLY1OCYwS04ZXIRBjtCKavCzqjCMNs0+k\n" +
            "sCmrDXOziRb02vW9QIRH96QDxbL3YEjt2c5SZxS6Yc453OaaeEjwR/vVPQvzZU5o\n" +
            "acRIkMlKlvBrYk8gwOayMGjQcJa37ERSWgBBs/blQ8u+18mdIv5JLBPfFfTlLPp+\n" +
            "RpC2LeK1uF6FyLMKnUtu6dEOilasBiiTuBB0gnB4xTsyi8BLsZ8sASP3DS00xE7l\n" +
            "Ki716Na3DY4FfrEeY+Id7Z/wsV7an/W4Jep3mbLy9JITlNWQvyrQXT3pR418TQcR\n" +
            "jUcQ1x8YDaB2hUySDf/d6Sp7ZdXfBnMTkpmwxTrGIcC1oEjSFifU47uPSSuBsQy3\n" +
            "iZIkX4WiDcsDE3cN7tEXBjiuOZFgBV/80WsFRo2WSGZ3IZzvyyO9NnlhJKJav6/x\n" +
            "ObBKDU9HYqHzTPcjPmdJqLodAxT0Zd926xg5aInHdq+jOHdgrgoSui/s6GiRIIqd\n" +
            "RsXxSDtYSEj9wH8y4mPWbOawjqJOcKbjDR0FpGObvxrGrO27SHvni2PU+9HA8yf9\n" +
            "HorTp0YlUs8YpmJ4l32r51qroUWpD47cophsLxiqDyOjoP22W49Csj1hErKOD36M\n" +
            "7KCksGkZHnwU1lvDsn3b//ExDx0WkPgqCM4dNVN/iFzfNrm2g105xkkgipGIhFHv\n" +
            "QrCAKuPZimjW8EhDXNjnveM7n/TBzghEgA4mEzpBfHnxfefdQr/6oRz6B6kth+Mp\n" +
            "xby6URsGjOMlfl5CidRBKgFo9QsWIJ1+ThwreoxVg0k722gRTdp81aYPglDXDW5g\n" +
            "SzTBFqxu7FXxG544XtcMkEM+YOl6tPOS15YoivXQUpzGcnKMLVuFrgBE1aeOCz1m\n" +
            "IzjMY87Yhvf4OFUWTEetEHHYVSPRleZvsc+ph3uaQ9Cpgxqq2NrboK/aHLwrYLL3\n" +
            "OFBW2jbtFYKX5cFSer83KluKbLUf3zy5gfAVPLseUdG4hriN3X5cZVFrflZPvb70\n" +
            "g3tuXfOgtQ2EcbL8ooBCXGUzT5woiN1eZojBMdk114oQUdlk52Qe1JBYqU0MY+QE\n" +
            "ryhyU72DIJdJCq7Hr9MQS2DvF64EW0eeqcllL4b54TymMI9A7VdAMs36bxIgaIVR\n" +
            "4I6XW8YQzsxEvtY9kdLiYUcmnckFbkmYxg6qQaLUEKK1Ht7Nlvc=\n" +
            "=z6qh\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testESSS() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(esss, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String esss = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQwAjqlZaLLZlpVjqv+XxnF1BZNEkvV0MvXMu489CKRoyE9g\n" +
            "HuJ3hJs1DMaIIuWHQNM/MXQJy09jCw7U1hOmr0WNgvJDQR4EFhbdTIFh8voihdbO\n" +
            "nsb+9jg09b5RhEbtg6H6ERtBZypT+GgbrlaIrpmpmoP0T4o1aycul8s+HPq6hBDs\n" +
            "+uPH/24F/JWQayJPpcBe1U/UdKndZ0Lc3xtXjalPNgOA0DhHX+l4TwhPkTEFWlO4\n" +
            "JzHwMZU2w4wzPcOqjoqD4/sZHDZsT6dMPzTguQRiQn4CtLrBYdApHeKnAV5NRhvO\n" +
            "6UBS3cJ/MSMe4owy3bDGIIcXKpgDe9Hi521hnk1d1K56qhP+4DFfXY8EKHU6hbvM\n" +
            "yunMJjS2i+cT6EKEKkuKGO+M5fQPIXRkIvkblM10yQgianRUBKswHR3ZbM72cK8P\n" +
            "qQVXk1xVyJSoIztRbA/IWQezBCnjj+NDMay8D+jMw7TE9GfopsG6wBNsxWlznAY+\n" +
            "/n3O0JtCZpYk2GPHgjCo0sW6ARRMmRkf/aqVttGjElgXn+pqe5s7rSBYn1fPcYOr\n" +
            "emqZkopmu4uZcoGbZRFpdVJ0/54ssHRbltmlOEZtnF1rGrHJbwgUrMJJENkZ4MS1\n" +
            "vvmoCTpnt62S9oGD+qItGq1n/PjnFMxY0xV8LZhEpN1eJm4v/KOEfCgDgzv+1AkK\n" +
            "6emdRhe6qXvJBhswO+aG+zAcx91QIjkIthmVP7NpTdwVWBOoXfvLa3rSdYttUP05\n" +
            "OaZ3agbcDvEKW+OVPagnlHRn4CHZQy4QWXA7A14+ZJ6KZgNa45D7Y0qOm5BJDqUV\n" +
            "cYjYJQ2B6S5Jo4F18Cy0AQC8lWUJn7uXazVFFG90HrPqgF6Fj5rUlN3Xu/ynFZTd\n" +
            "nvDNXoOzpVbh7FWw0kl8cRaBvERJ1BYktQzgsJ97ul18ostspafo/U/Asiqld9jw\n" +
            "3fYQqTWPmg3IkamLeuMEnqXnOLtUcuQG8uL8by4eeTqCP6Nywei3KtnwzFVyfKoz\n" +
            "w2g++/mwk+v/w4oKyuiNi7A53ngEV7AketcHsj/Pz8p3m0JSSysJZeK9qQqZxlpQ\n" +
            "e5bWmkt91FGuudeWPmRtH2JXJAfCjJ60wvVdWDRKfX4l6Z2+b7Qx0mEW7TYqT/hi\n" +
            "mMn6dbUbtU+6qxul8dh9bRe4wBC9wmijQb6vKg+s41uTEZpLPAQpynl+iP1dHb3w\n" +
            "3RTj2IRZjyLbsIEO4EIugZaKshFUtqA7pSU9FnZIDIRNSfQSVZkhmfbCRWaINlRd\n" +
            "XIoI/JG1Pqb3ErdVMDAgRH/6uiWS6l5sZysMnwsk+A1I3lqJ2YW6C6I/FXzSmQIy\n" +
            "dhQ93L9vXQAZF6tC1AvZWn73ehPC+b9qtzfStLCXnXhBtyT/SkfYCuYat4+wZgxL\n" +
            "dDi0zONngZ2IhPtsTeMw7LhZirHAFIjvQFx2tIh5e4VoO0+E8Tf6gnMwFyw0N8Bj\n" +
            "2Jm5+kvoxmwwPeAXq/9gmKGz/qVY7iQ1c+XHan1qj+E59u8bbURdEzLnbzZ8j1zV\n" +
            "7fsQAt14dz/gGv6gSqRpE7gTFGRR5Mm+UFVzGhLZXUuyxtdPMX3id2e949n/FQ/z\n" +
            "US4g3/xNmUUKom8ryk4t16dwwepS1lslm9eciuWTPAzjyRySLtUvfB1EPcAfhLho\n" +
            "IqFvTTZqP/AhVIeaMRfAb3qR5TP6HdDGVVkq46Qsw8z3Cu9itu8osESGYlA+LoxA\n" +
            "VfrbV9It2QdXbsSShlArDOxqC7z8n2M9ry7gVowbOK58jSrkzs0EsNKDfD0kx6ro\n" +
            "GZFxtoBDvJ+2r+Vbe9r+0NolCuXpkOIUKdhXQl8sEG84NouggXUHY/slI1nZr7r+\n" +
            "iJ7Tlm08DRSgUaHJZc+pl8o2Ffev2+px78Ifu54T+NEG42HqoiMh4V1BBaJabRSE\n" +
            "VxZPM7TNKT5zWiEUrwR/JCBlpTyANCS3dwcyeeWsxdFFdmwyQt57HgbHCSTpUjND\n" +
            "f45d3B3R4vxktd4jISQVNWZWqgpBL30CE6LYJG519Pj35O8CL537qpRL/z5lU1Km\n" +
            "PsjJA+Byw8oY8KPd1jQe+mIGMaeD1V2fgEgwKWj8GZuZ5keQFanlbI1IpV+YrkFQ\n" +
            "VaWjRIgCarsVRWe0LVRVb+NcfjeHRGwlTPMBjvCdgd0znYGU7x3mBUbx5/Ui9dF+\n" +
            "l1TcMzmzErQMFnqB27046YET1KfQxg3f8CIIOIAcS7fygFmIcLatsgPbFzLbIsVl\n" +
            "Yklo2VUmyrIYlbfGti5No6reUYDkFid7oKKR0e0cuAv7rdQZos9lQmK40T8hIOG3\n" +
            "rOI5RturZ1ZUHji/6qjiDmc3/eRhzombsm/INCnhRl1Pxr740YWQJn/cDU9nr0Rm\n" +
            "N6uBptK9ap8/9jv/F8wu790BKt0NTuK9GgWGdMxvsnBwS40PjPGsbclUyTGoeqe4\n" +
            "udq89pCzu8Ltf0nIeIdIY7YTQUvDJPqXvIoVDlCF+hbNg7WzfXQDeroZ1YZcreWb\n" +
            "XU3f5J5QozOVsqVajmRNALyZ0GYHGqkyWDaWTqNNODU+Kha1ghp+hZuVM12I7BRv\n" +
            "uhl/rn1Ao/IVkJ9gNkQ7w4Hs8F7fCIGTVYWYEyGyhUlVVCeJs5J+GGed+MeUUAx9\n" +
            "pFhvGEvEsZapZ4JFX4Imf8pF3bVXlgAiv5KcZbC80yis4cpyCqVdyhlK0mx8UWjr\n" +
            "OycSHXikcsSUtoZz2VoVQziMkhOHaKQR+BqoGNIT2DF678FVWJbH1L5ABt8=\n" +
            "=+H1Y\n" +
            "-----END PGP MESSAGE-----\n";

    @Test
    public void testSESCS() throws PGPException, IOException {
        OpenPgpMetadata metadata = processMessage(sescs, secretKeys, certificate);
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerified());
    }

    public static final String sescs = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "xA0DAAoB+/zIKgFeczABwcDMA3wvqk35PDeyAQv/Tdn7QWZryV9Bu3t0kq0zyil3\n" +
            "DiqLiBgphH8GD5HswNss5ThOPRPxN2/3xht1B4V5crB1sTgSuW1eLMTQhMqe/coA\n" +
            "UJND2FrBmJmnZjPGt6uPmngZxn8mQ3h1gt0sqXaDA7cSUwZeLMslMPqScHPAxUvA\n" +
            "qkmU9y3chg97ykclNTamVhfXF969ARQ1PrVyFUhkbBx1SplBxDzkvN2w9QucyMgf\n" +
            "yG+xPnN+d6o4A06pvRckJGPxI5bFsexHc4Wf0YfP/B+49BpsBqd0DuxDj1Lf7iI9\n" +
            "28jfxOKkOttXkH4yMiEMpaiIiR3jFYRbtjjeEMtrKwLfMzYaeJA0uh52qKVHMFVI\n" +
            "bbG20vGeRQUzhziOTvfvVyEymdWvHWB32QNsSqa9PBp9K2oAOGSlqi2K7rBBYcsd\n" +
            "renw6/0+hMHYZet+QQkcFqJBEh/neCWorCahCqAdaGCV9lo9kbpZ5keikL9uV8D1\n" +
            "hgIO1v0kFPMjuEYELaqcIAIkqR/XdN2nTcIGJDMe0sPDAUkNNohwVYuv5KFpT4hW\n" +
            "XoJ1557QlqGBgs95eEQnzncup+4MV/g3JfP5N+IFNUOlKq10aEoTEAbbTKHWt20Q\n" +
            "6Cae8Y1nBUAAUbvVd/jQHBIQWHSFnw40yQEqaDZg9HE1f6DjVRSGfB8tOFH4H4CY\n" +
            "pCvmYkYgrTyxK5Q4Wx1xd/5jcExz8TsZnsMk7eUXD4WnaMS/MInEWZHMNbRpmRiU\n" +
            "COv5UZY9ptbmydk2WAs97DhE+JzO6Og31CkyNcrkVqOC31tro5bNtYSZw62shAr3\n" +
            "W6GM4QTMbpZ3VVZ8K8ihCL5SNtQrJ6O7tg1ZnvFfP08CC5qQwmy+yBIvTf46e8g5\n" +
            "LrntZTz9wh57X6oAb+G+NYuPaQsxwvuy2NLtEMcKWLCO3/QrqQU2C1Yr6WdQdc+Z\n" +
            "W6LUhFc2xLBeRrHmVeOHs4+Yio32qyqB/ju7EBMgd1zA/F0JHx6htpo0C2B1Noph\n" +
            "h/I5qns3XGGdBhWKkvTpOS8JDeGn7MxZL+vp1nrs3mzrajMRDqloKRD0AgsxOGZ9\n" +
            "GjzMLwZ4kpIBz/RBy0sl6QqIlOZlipX070Rd0/xPDIWAlcZmo/qrF7OFPGM+Oi7h\n" +
            "W9cl4njX4V07y/t5fNsK57Bb/o1VXEopUhTHPQNpQUQo/DCJQKkK6ca42w8ryuBR\n" +
            "G+PK896XrnBcdHrqt7D2z0eSK8c/oSB5DIEw+UT6X/c3klmiWMPWsnKuZbjCoO+L\n" +
            "W55au2SCWDlUoevj9L3JwgwknoGzHSShptj62VT0OX/zECTymBstanZs8P2pn1Vk\n" +
            "mYJ6QU300ikj7oFsRYY3j3fvvfqdVduDnQYeZyy6330oAIL89kEorxV4I9aBuYZF\n" +
            "3jFkxJb0Yifpq08OrxcsQhihCQYF5yk1Jx74J9TvRT2TpPEO9H9iQ3qtXU3efoOa\n" +
            "+gf3ZbUPrTZPRw16qlQEzBLOFEIfpJ11NpYUIJ5jkhMMHGgx6NusJPNxT62qUbQm\n" +
            "ZKkFExr2PO+JxWWW/1wJmACdJ87VOm35tI3/IxndOWBUzLvjshR1GJosjVmUpm8i\n" +
            "7o6V2vYilsfGamQoZuBTd21dZOQvEQoCBJ8F6em/gvLzA69FguYrpgvVJMB4S6ng\n" +
            "ySk/8PqKERUCqGs53sDZGGXuMsTz2r1YxUUuNz8doNna8g8LNteRe6Ybg2GpY4dA\n" +
            "RMJynlXXeVcP6BFsJKSiP4z0NwhZyESAaWpo9PDE/bTKOV8j6zuPKmTv+DS46teA\n" +
            "RChiVPd69OUGa4mj4dbM5a9wSHokQN5kES5g8CHgn6zbOwIDRHuwhaE0d1/SM0qc\n" +
            "RptxbpqP8PaHl3eCUlT73UDG9ws0P+2Z8EtgoPBfg7wlCeJiFwi47eeIXwco/VGX\n" +
            "KiF3nObw65H1e0yVfWIB7fSO5kc77SPEv8GllXoG5iJjQQAtRaKG6PoASRXn2sj6\n" +
            "mzH+EJsapdJs3O9pIHyVutssJHA/8KTxn4cFRVMygEZVmXyB6ucozTbyJQu+NRMY\n" +
            "ykaSTKPiLB2Y4YvafAAUBktrba8M/RWjM6eh8YCt0u5sRr9CwsE7BAABCgBvBYJj\n" +
            "KwcFCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn\n" +
            "cC5vcmewhjhWDzweF1tkD58gx4AYLZKiV0Xa4x3FeZrmqPHenhYhBNGmbhojsYLJ\n" +
            "mA94jPv8yCoBXnMwAAC85Qv/RUydgcbfqXFliuZtfsIsRL/Ws3FokvZ3oas2NMlI\n" +
            "+Utmv66FYT22RbpK57zOdBstDPje0/tdwKim5iFvhYe0SXtSiiCwFA1SyGURkACD\n" +
            "eVpbOPTsLEnknMFD2GO99F2uFeo9K2jpZnQYkauHiICoCRuKfIskL+lLRGErN7KN\n" +
            "6U3GG9MX3wqyU6AzjWEhTIg2AzcXDSDdFEpbvGIDjVO8YNJnqgwbRlBZaSfCoeOT\n" +
            "ldIEzuqraTnqJIT2bkeVzzpg7EMenuTDJdH+bWjtHf7S2YV8ntiN7Xj3yj4sYHvq\n" +
            "wLonw2LiDcvHpQKx8VGC7FloRLAbhnbBf1+8GYhArUkqwaW+j/xoY+rvfk3Ql/eg\n" +
            "Cr81vAcz5I3e+jA28dECBLjNgEEicz2vRtXSQPbRilyOureGkLpAVLz/DvRXz7gJ\n" +
            "saTMCVQ09tuQnfQy3GcFKUuuFLLasG6EgH4cieIymCK5fMNu4zpiXo3glUfjuCjb\n" +
            "MStNYvYXOxNZM56Y9uWRr1BL\n" +
            "=Mf+w\n" +
            "-----END PGP MESSAGE-----";
}
