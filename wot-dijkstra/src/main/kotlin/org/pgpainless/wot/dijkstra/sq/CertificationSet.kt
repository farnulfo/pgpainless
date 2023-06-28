// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq

data class CertificationSet(
        val issuer: CertSynopsis,
        val target: CertSynopsis,
        val certifications: MutableMap<String?, MutableList<Certification>>) {

    companion object {

        @JvmStatic
        fun empty(issuer: CertSynopsis, target: CertSynopsis): CertificationSet {
            return CertificationSet(issuer, target, HashMap())
        }

        @JvmStatic
        fun fromCertification(certification: Certification) : CertificationSet {
            val set = empty(certification.issuer, certification.target)
            set.add(certification)
            return set
        }
    }

    fun merge(other: CertificationSet) {
        if (other == this) {
            return
        }

        require(issuer.fingerprint == other.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == other.target.fingerprint) { "Target fingerprint mismatch." }

        for (userId in other.certifications.keys) {
            for (certification in other.certifications[userId]!!) {
                add(certification)
            }
        }
    }

    fun add(certification : Certification) {
        require(issuer.fingerprint == certification.issuer.fingerprint) { "Issuer fingerprint mismatch." }
        require(target.fingerprint == certification.target.fingerprint) { "Target fingerprint mismatch." }

        var certificationsForUserId: MutableList<Certification>? = certifications[certification.userId]
        if (certificationsForUserId == null) {
            certificationsForUserId = ArrayList()
            certifications[certification.userId] = certificationsForUserId
        }
        certificationsForUserId.add(certification)
    }

    override fun toString(): String {
        return "$certifications"
    }
}