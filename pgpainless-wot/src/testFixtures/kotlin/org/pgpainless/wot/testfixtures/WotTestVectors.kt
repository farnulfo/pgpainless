package org.pgpainless.wot.testfixtures

import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.Trustworthiness
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.subpackets.CertificationSubpackets
import org.pgpainless.util.Passphrase
import java.io.IOException
import java.io.InputStream

class WotTestVectors {

    companion object {

        @JvmStatic
        fun getTestResource(resource: String): InputStream {
            val input = WotTestVectors::class.java.classLoader.getResourceAsStream(resource)
            return requireNotNull(input) {
                "Unknown resource $resource"
            }
        }

        @JvmStatic
        val freshFooBankCaKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankCaKey.asc"))!!

        @JvmStatic
        val freshFooBankCaCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankCaCert.asc"))!!

        @JvmStatic
        val fooBankCaPassphrase = "superS3cureP4ssphrase"

        @JvmStatic
        val fooBankCaProtector: SecretKeyRingProtector = SecretKeyRingProtector.unlockAnyKeyWith(
                Passphrase.fromPassword(fooBankCaPassphrase))

        @JvmStatic
        val freshFooBankEmployeeKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankEmployeeKey.asc"))!!

        @JvmStatic
        val freshFooBankEmployeeCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankEmployeeCert.asc"))!!

        @JvmStatic
        val fooBankEmployeePassphrase = "iLoveWorking@FooBank"

        @JvmStatic
        val fooBankEmployeeProtector: SecretKeyRingProtector = SecretKeyRingProtector.unlockAnyKeyWith(
                Passphrase.fromPassword(fooBankEmployeePassphrase))

        @JvmStatic
        val freshFooBankAdminKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankAdminKey.asc"))!!

        @JvmStatic
        val freshFooBankAdminCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankAdminCert.asc"))!!

        @JvmStatic
        val fooBankAdminPassphrase = "keepFooBankSecure"

        @JvmStatic
        val fooBankAdminProtector: SecretKeyRingProtector = SecretKeyRingProtector.unlockAnyKeyWith(
                Passphrase.fromPassword(fooBankAdminPassphrase))

        @JvmStatic
        val freshFooBankCustomerKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankCustomerKey.asc"))!!

        @JvmStatic
        val freshFooBankCustomerCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/foobankCustomerCert.asc"))!!

        @JvmStatic
        val fooBankCustomerProtector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()

        @JvmStatic
        val freshBarBankCaKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/barbankCaKey.asc"))!!

        @JvmStatic
        val freshBarBankCaCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/barbankCaCert.asc"))!!

        @JvmStatic
        val barBankCaProtector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()

        @JvmStatic
        val freshBarBankEmployeeKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/barbankEmployeeKey.asc"))!!

        @JvmStatic
        val freshBarBankEmployeeCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/barbankEmployeeCert.asc"))!!

        @JvmStatic
        val freshFakeFooBankEmployeeKey: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(
                getTestResource("test_vectors/freshly_generated/fakeFoobankEmployeeKey.asc"))!!

        @JvmStatic
        val freshFakeFooBankEmployeeCert: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(
                getTestResource("test_vectors/freshly_generated/fakeFoobankEmployeeCert.asc"))!!


        @Throws(IOException::class)
        fun getCrossSignedBarBankCaCert(): PGPPublicKeyRing? {
            return PGPainless.readKeyRing().publicKeyRing(getTestResource("cross_signed/barbankCaCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedBarBankEmployeeCert(): PGPPublicKeyRing? {
            return PGPainless.readKeyRing().publicKeyRing(getTestResource("cross_signed/barbankEmployeeCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedFooBankAdminCert(): PGPPublicKeyRing? {
            return PGPainless.readKeyRing().publicKeyRing(getTestResource("cross_signed/foobankAdminCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedFooBankCaCert(): PGPPublicKeyRing? {
            return PGPainless.readKeyRing().publicKeyRing(getTestResource("cross_signed/foobankCaCert.asc"))
        }

        @Throws(IOException::class)
        fun getCrossSignedFooBankEmployeeCert(): PGPPublicKeyRing? {
            return PGPainless.readKeyRing().publicKeyRing(getTestResource("cross_signed/foobankEmployeeCert.asc"))
        }

        // Generate cross signed test vectors from freshly generated
        @Throws(IOException::class, PGPException::class)
        fun crossSign() {
            val fooBankRegex = "<[^>]+[@.]foobank\\.com>$"
            val barBankRegex = "<[^>]+[@.]barbank\\.com>$"

            // Foo CA signs Foo Employee
            val caCertifiedFooBankEmployeeCert = PGPainless.certify()
                    .userIdOnCertificate("Foo Bank Employee <employee@foobank.com>", freshFooBankEmployeeCert)
                    .withKey(freshFooBankCaKey, fooBankCaProtector)
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.addNotationData(false, "affiliation@foobank.com", "employee")
                        }
                    })
                    .certifiedCertificate

            // Foo CA signs Foo Admin
            val caCertifiedFooBankAdminCert = PGPainless.certify()
                    .userIdOnCertificate("Foo Bank Admin <admin@foobank.com>", freshFooBankAdminCert)
                    .withKey(freshFooBankCaKey, fooBankCaProtector)
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.addNotationData(false, "affiliation@foobank.com", "administrator")
                        }
                    })
                    .certifiedCertificate

            // Foo Employee delegates trust to Foo CA
            val employeeDelegatedCaCert = PGPainless.certify()
                    .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankEmployeeKey, fooBankEmployeeProtector)
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.setRegularExpression(fooBankRegex)
                        }
                    })
                    .certifiedCertificate

            // Foo Admin delegates trust to Foo CA
            val adminDelegatedCaCert = PGPainless.certify()
                    .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankAdminKey, fooBankAdminProtector)
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.setRegularExpression(fooBankRegex)
                        }
                    })
                    .certifiedCertificate

            // Customer delegates trust to Foo CA
            val customerDelegatedCaCert = PGPainless.certify()
                    .certificate(freshFooBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankCustomerKey, SecretKeyRingProtector.unprotectedKeys())
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.setRegularExpression(fooBankRegex)
                        }
                    })
                    .certifiedCertificate
            var mergedFooCa = PGPPublicKeyRing.join(employeeDelegatedCaCert, adminDelegatedCaCert)
            mergedFooCa = PGPPublicKeyRing.join(mergedFooCa, customerDelegatedCaCert)

            // Foo Admin delegates trust to Bar CA
            val fooAdminDelegatedBarCa = PGPainless.certify()
                    .certificate(freshBarBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshFooBankAdminKey, fooBankAdminProtector)
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.setRegularExpression("<[^>]+[@.]barbank\\.com>$")
                        }
                    }).certifiedCertificate

            // Bar Employee delegates Bar CA
            val barEmployeeDelegatesBarCa = PGPainless.certify()
                    .certificate(freshBarBankCaCert, Trustworthiness.fullyTrusted().introducer())
                    .withKey(freshBarBankEmployeeKey, SecretKeyRingProtector.unprotectedKeys())
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.setRegularExpression(barBankRegex)
                        }
                    })
                    .certifiedCertificate
            val mergedBarCa = PGPPublicKeyRing.join(fooAdminDelegatedBarCa, barEmployeeDelegatesBarCa)

            // Bar CA signs Bar Employee
            val barCaCertifiedEmployeeCert = PGPainless.certify()
                    .userIdOnCertificate("Bar Bank Employee <employee@barbank.com>", freshBarBankEmployeeCert)
                    .withKey(freshBarBankCaKey, SecretKeyRingProtector.unprotectedKeys())
                    .buildWithSubpackets(object : CertificationSubpackets.Callback {
                        override fun modifyHashedSubpackets(hashedSubpackets: CertificationSubpackets) {
                            hashedSubpackets.addNotationData(false, "affiliation@barbank.com", "employee")
                        }
                    })
                    .certifiedCertificate

            // CHECKSTYLE:OFF
            println("Foo Employee")
            println(PGPainless.asciiArmor(caCertifiedFooBankEmployeeCert))
            println("Foo Admin")
            println(PGPainless.asciiArmor(caCertifiedFooBankAdminCert))
            println("Foo CA")
            println(PGPainless.asciiArmor(mergedFooCa))
            println("Bar CA")
            println(PGPainless.asciiArmor(mergedBarCa))
            println("Bar Employee")
            println(PGPainless.asciiArmor(barCaCertifiedEmployeeCert))
            // CHECKSTYLE:ON
        }
    }
}