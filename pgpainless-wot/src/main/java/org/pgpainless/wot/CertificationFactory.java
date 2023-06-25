// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.bcpg.sig.TrustSignature;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil;
import org.pgpainless.wot.dijkstra.sq.CertSynopsis;
import org.pgpainless.wot.dijkstra.sq.Certification;
import org.pgpainless.wot.dijkstra.sq.Depth;
import org.pgpainless.wot.dijkstra.sq.Optional;
import org.pgpainless.wot.dijkstra.sq.RegexSet;

/**
 * Factory class for creating {@link Certification} objects from {@link PGPSignature PGPSignatures}.
 * The purpose of this class is to minimize the number of PGPainless / Bouncycastle class dependencies in wot-dijkstra.
 */
public class CertificationFactory {

    /**
     * Create a {@link Certification} object from a delegation signature.
     *
     * @param issuer signature issuer certificate
     * @param target signature target certificate
     * @param signature signature
     * @return certification
     */
    public static Certification fromDelegation(CertSynopsis issuer,
                                               CertSynopsis target,
                                               PGPSignature signature) {
        return fromSignature(issuer, Optional.empty(), target, signature);
    }

    /**
     * Create a {@link Certification} object from a certification signature.
     *
     * @param issuer signature issuer certificate
     * @param targetUserId signature target user ID
     * @param target signature target certificate
     * @param signature signature
     * @return certification
     */
    public static Certification fromCertification(CertSynopsis issuer,
                                                  String targetUserId,
                                                  CertSynopsis target,
                                                  PGPSignature signature) {
        return fromSignature(issuer, Optional.just(targetUserId), target, signature);
    }

    /**
     * Create a {@link Certification} object from a signature.
     *
     * @param issuer signature issuer certificate
     * @param targetUserId optional signature target user ID
     * @param target signature target certificate
     * @param signature signature
     * @return certification
     */
    public static Certification fromSignature(CertSynopsis issuer,
                                              Optional<String> targetUserId,
                                              CertSynopsis target,
                                              PGPSignature signature) {
        return new Certification(
                issuer,
                target,
                targetUserId,
                SignatureSubpacketsUtil.getSignatureCreationTime(signature).getTime(),
                Optional.maybe(SignatureSubpacketsUtil.getSignatureExpirationTimeAsDate(signature)),
                SignatureSubpacketsUtil.isExportable(signature),
                getTrustAmountFrom(signature),
                getTrustDepthFrom(signature),
                regexSetFrom(signature));
    }

    /**
     * Extract the trust amount from the signature.
     * If the signature has no {@link TrustSignature} subpacket, return a default value of 120.
     *
     * @param signature signature
     * @return trust amount
     */
    private static int getTrustAmountFrom(PGPSignature signature) {
        TrustSignature packet = SignatureSubpacketsUtil.getTrustSignature(signature);
        if (packet != null) {
            return packet.getTrustAmount();
        }
        return 120; // default value
    }

    /**
     * Extract the trust depth from the signature.
     * If the signature has no {@link TrustSignature} subpacket, return a default value of 0.
     *
     * @param signature signature
     * @return trust depth
     */
    private static Depth getTrustDepthFrom(PGPSignature signature) {
        TrustSignature packet = SignatureSubpacketsUtil.getTrustSignature(signature);
        if (packet != null) {
            return Depth.auto(packet.getDepth());
        }
        return Depth.limited(0);
    }

    /**
     * Extract a {@link RegexSet} from the signature.
     * If the signature has no {@link RegularExpression} subpacket, the result will equate to a wildcard.
     *
     * @param signature signature
     * @return regex set
     */
    private static RegexSet regexSetFrom(PGPSignature signature) {
        List<RegularExpression> regexList = SignatureSubpacketsUtil.getRegularExpressions(signature);
        List<String> stringList = new ArrayList<>();
        for (RegularExpression regex : regexList) {
            stringList.add(regex.getRegex());
        }
        return RegexSet.fromExpressionList(stringList);
    }
}
