// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.Trustworthiness;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.CertificationSubpackets;
import org.pgpainless.util.Passphrase;

public class WotTestVectors {

    private static WotTestVectors INSTANCE = null;

    public static WotTestVectors getTestVectors() {
        if (INSTANCE == null) {
            INSTANCE = new WotTestVectors();
        }
        return INSTANCE;
    }

    public PGPSecretKeyRing getFreshFooBankCaKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCaKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankCaCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCaCert.asc"));
    }

    public String getFooBankCaPassphrase() {
        return "superS3cureP4ssphrase";
    }

    public SecretKeyRingProtector getFooBankCaProtector() {
        return SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(getFooBankCaPassphrase()));
    }

    public PGPSecretKeyRing getFreshFooBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankEmployeeCert.asc"));
    }

    public String getFooBankEmployeePassphrase() {
        return "iLoveWorking@FooBank";
    }

    public SecretKeyRingProtector getFooBankEmployeeProtector() {
        return SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(getFooBankEmployeePassphrase()));
    }

    public PGPSecretKeyRing getFreshFooBankAdminKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankAdminKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankAdminCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankAdminCert.asc"));
    }

    public String getFooBankAdminPassphrase() {
        return "keepFooBankSecure";
    }

    public SecretKeyRingProtector getFooBankAdminProtector() {
        return SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(getFooBankAdminPassphrase()));
    }

    public PGPSecretKeyRing getFreshFooBankCustomerKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCustomerKey.asc"));
    }

    public PGPPublicKeyRing getFreshFooBankCustomerCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/foobankCustomerCert.asc"));
    }

    public PGPSecretKeyRing getFreshBarBankCaKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/barbankCaKey.asc"));
    }

    public PGPPublicKeyRing getFreshBarBankCaCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/barbankCaCert.asc"));
    }

    public PGPSecretKeyRing getFreshBarBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/barbankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshBarBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/barbankEmployeeCert.asc"));
    }

    public PGPSecretKeyRing getFreshFakeFooBankEmployeeKey() throws IOException {
        return PGPainless.readKeyRing().secretKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/fakeFoobankEmployeeKey.asc"));
    }

    public PGPPublicKeyRing getFreshFakeFooBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("test_vectors/freshly_generated/fakeFoobankEmployeeCert.asc"));
    }

    public PGPPublicKeyRing getCrossSignedBarBankCaCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("cross_signed/barbankCaCert.asc"));
    }

    public PGPPublicKeyRing getCrossSignedBarBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("cross_signed/barbankEmployeeCert.asc"));
    }

    public PGPPublicKeyRing getCrossSignedFooBankAdminCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("cross_signed/foobankAdminCert.asc"));
    }

    public PGPPublicKeyRing getCrossSignedFooBankCaCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("cross_signed/foobankCaCert.asc"));
    }

    public PGPPublicKeyRing getCrossSignedFooBankEmployeeCert() throws IOException {
        return PGPainless.readKeyRing().publicKeyRing(getTestResourceInputStream("cross_signed/foobankEmployeeCert.asc"));
    }

    // Generate cross signed test vectors from freshly generated
    public void crossSign() throws IOException, PGPException {
        PGPSecretKeyRing freshFooBankCaKey = getFreshFooBankCaKey();
        PGPPublicKeyRing freshFooBankCaCert = getFreshFooBankCaCert();

        PGPSecretKeyRing freshFooBankEmployeeKey = getFreshFooBankEmployeeKey();
        PGPPublicKeyRing freshFooBankEmployeeCert = getFreshFooBankEmployeeCert();

        PGPSecretKeyRing freshFooBankAdminKey = getFreshFooBankAdminKey();
        PGPPublicKeyRing freshFooBankAdminCert = getFreshFooBankAdminCert();

        PGPSecretKeyRing freshFooBankCustomerKey = getFreshFooBankCustomerKey();
        PGPPublicKeyRing freshFooBankCustomerCert = getFreshFooBankCustomerCert();

        PGPSecretKeyRing freshBarBankCaKey = getFreshBarBankCaKey();
        PGPPublicKeyRing freshBarBankCaCert = getFreshBarBankCaCert();

        PGPSecretKeyRing freshBarBankEmployeeKey = getFreshBarBankEmployeeKey();
        PGPPublicKeyRing freshBarBankEmployeeCert = getFreshBarBankEmployeeCert();

        PGPSecretKeyRing freshFakeFooBankEmployeeKey = getFreshFakeFooBankEmployeeKey();
        PGPPublicKeyRing freshFakeFooBankEmployeeCert = getFreshFakeFooBankEmployeeCert();

        final String fooBankRegex = "<[^>]+[@.]foobank\\.com>$";
        final String barBankRegex = "<[^>]+[@.]barbank\\.com>$";

        // Foo CA signs Foo Employee
        PGPPublicKeyRing caCertifiedFooBankEmployeeCert = PGPainless.certify()
                .userIdOnCertificate("Foo Bank Employee <employee@foobank.com>", freshFooBankEmployeeCert)
                .withKey(freshFooBankCaKey, getFooBankCaProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.addNotationData(false, "affiliation@foobank.com", "employee");
                    }
                })
                .getCertifiedCertificate();

        // Foo CA signs Foo Admin
        PGPPublicKeyRing caCertifiedFooBankAdminCert = PGPainless.certify()
                .userIdOnCertificate("Foo Bank Admin <admin@foobank.com>", freshFooBankAdminCert)
                .withKey(freshFooBankCaKey, getFooBankCaProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.addNotationData(false, "affiliation@foobank.com", "administrator");
                    }
                })
                .getCertifiedCertificate();

        // Foo Employee delegates trust to Foo CA
        PGPPublicKeyRing employeeDelegatedCaCert = PGPainless.certify()
                .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankEmployeeKey, getFooBankEmployeeProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression(fooBankRegex);
                    }
                })
                .getCertifiedCertificate();

        // Foo Admin delegates trust to Foo CA
        PGPPublicKeyRing adminDelegatedCaCert = PGPainless.certify()
                .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankAdminKey, getFooBankAdminProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression(fooBankRegex);
                    }
                })
                .getCertifiedCertificate();

        // Customer delegates trust to Foo CA
        PGPPublicKeyRing customerDelegatedCaCert = PGPainless.certify()
                .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankCustomerKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression(fooBankRegex);
                    }
                })
                .getCertifiedCertificate();

        PGPPublicKeyRing mergedFooCa = PGPPublicKeyRing.join(employeeDelegatedCaCert, adminDelegatedCaCert);
        mergedFooCa = PGPPublicKeyRing.join(mergedFooCa, customerDelegatedCaCert);

        // Foo Admin delegates trust to Bar CA
        PGPPublicKeyRing fooAdminDelegatedBarCa = PGPainless.certify()
                .certificate(freshBarBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshFooBankAdminKey, getFooBankAdminProtector())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression("<[^>]+[@.]barbank\\.com>$");
                    }
                }).getCertifiedCertificate();

        // Bar Employee delegates Bar CA
        PGPPublicKeyRing barEmployeeDelegatesBarCa = PGPainless.certify()
                .certificate(freshBarBankCaCert, Trustworthiness.fullyTrusted().introducer())
                .withKey(freshBarBankEmployeeKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.setRegularExpression(barBankRegex);
                    }
                })
                .getCertifiedCertificate();

        PGPPublicKeyRing mergedBarCa = PGPPublicKeyRing.join(fooAdminDelegatedBarCa, barEmployeeDelegatesBarCa);

        // Bar CA signs Bar Employee
        PGPPublicKeyRing barCaCertifiedEmployeeCert = PGPainless.certify()
                .userIdOnCertificate("Bar Bank Employee <employee@barbank.com>", freshBarBankEmployeeCert)
                .withKey(freshBarBankCaKey, SecretKeyRingProtector.unprotectedKeys())
                .buildWithSubpackets(new CertificationSubpackets.Callback() {
                    @Override
                    public void modifyHashedSubpackets(CertificationSubpackets hashedSubpackets) {
                        hashedSubpackets.addNotationData(false, "affiliation@barbank.com", "employee");
                    }
                })
                .getCertifiedCertificate();

        // CHECKSTYLE:OFF
        System.out.println("Foo Employee");
        System.out.println(PGPainless.asciiArmor(caCertifiedFooBankEmployeeCert));

        System.out.println("Foo Admin");
        System.out.println(PGPainless.asciiArmor(caCertifiedFooBankAdminCert));

        System.out.println("Foo CA");
        System.out.println(PGPainless.asciiArmor(mergedFooCa));

        System.out.println("Bar CA");
        System.out.println(PGPainless.asciiArmor(mergedBarCa));

        System.out.println("Bar Employee");
        System.out.println(PGPainless.asciiArmor(barCaCertifiedEmployeeCert));
        // CHECKSTYLE:ON
    }

    private static InputStream getTestResourceInputStream(String resource) {
        InputStream inputStream = WotTestVectors.class.getClassLoader().getResourceAsStream(resource);
        if (inputStream == null) {
            throw new IllegalArgumentException(String.format("Unknown resource %s", resource));
        }
        return inputStream;
    }
}
