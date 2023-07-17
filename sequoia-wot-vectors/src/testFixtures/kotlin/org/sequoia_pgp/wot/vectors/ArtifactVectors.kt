// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: BSD-3-Clause

package org.sequoia_pgp.wot.vectors

import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.policy.Policy
import org.pgpainless.wot.KeyRingCertificateStore
import org.pgpainless.wot.WebOfTrust
import org.pgpainless.wot.network.Network
import org.pgpainless.wot.network.ReferenceTime
import java.io.File
import java.io.InputStream
import java.lang.IllegalArgumentException
import java.nio.file.Files
import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.*
import kotlin.io.path.outputStream

interface ArtifactVectors {

    val tempFilePrefix: String

    val tempKeyRingFile: File
        get() {
            val path = Files.createTempFile(tempFilePrefix, ".pgp")

            val outputStream = path.outputStream()
            Streams.pipeAll(keyRingInputStream(), outputStream)
            outputStream.close()

            val file = path.toFile()
            file.deleteOnExit()
            return file
        }

    private fun parseDate(string: String): Date {
        return try {
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss z")
                    .apply { timeZone = TimeZone.getTimeZone("UTC") }
                    .parse(string)
        } catch (e: ParseException) {
            SimpleDateFormat("yyyy-MM-dd")
                    .apply {timeZone = TimeZone.getTimeZone("UTC") }
                    .parse(string)
        } catch (e: ParseException) {
            throw IllegalArgumentException(e)
        }
    }

    fun parseReferenceTime(string: String): ReferenceTime {
        return ReferenceTime.timestamp(parseDate(string))
    }

    fun getResourceName(): String

    fun getNetworkAt(referenceTime: ReferenceTime = ReferenceTime.now(), policy: Policy = PGPainless.getPolicy()): Network {
        val inputStream = keyRingInputStream()
        val keyRing = PGPainless.readKeyRing().publicKeyRingCollection(inputStream)
        val store = KeyRingCertificateStore(keyRing)
        return WebOfTrust(store).buildNetwork(policy, referenceTime)
    }

    fun keyRingInputStream(): InputStream {
        return ArtifactVectors::class.java.classLoader.getResourceAsStream(getResourceName())!!
    }




}