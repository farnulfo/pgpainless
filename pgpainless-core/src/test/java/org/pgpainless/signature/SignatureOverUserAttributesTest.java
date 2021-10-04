/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

public class SignatureOverUserAttributesTest {

    private static final byte[] image = new byte[] {(byte) -1, (byte) -40, (byte) -1, (byte) -32, (byte) 0, (byte) 16, (byte) 74, (byte) 70, (byte) 73, (byte) 70, (byte) 0, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 44, (byte) 1, (byte) 44, (byte) 0, (byte) 0, (byte) -1, (byte) -2, (byte) 0, (byte) 19, (byte) 67, (byte) 114, (byte) 101, (byte) 97, (byte) 116, (byte) 101, (byte) 100, (byte) 32, (byte) 119, (byte) 105, (byte) 116, (byte) 104, (byte) 32, (byte) 71, (byte) 73, (byte) 77, (byte) 80, (byte) -1, (byte) -30, (byte) 2, (byte) -80, (byte) 73, (byte) 67, (byte) 67, (byte) 95, (byte) 80, (byte) 82, (byte) 79, (byte) 70, (byte) 73, (byte) 76, (byte) 69, (byte) 0, (byte) 1, (byte) 1, (byte) 0, (byte) 0, (byte) 2, (byte) -96, (byte) 108, (byte) 99, (byte) 109, (byte) 115, (byte) 4, (byte) 48, (byte) 0, (byte) 0, (byte) 109, (byte) 110, (byte) 116, (byte) 114, (byte) 82, (byte) 71, (byte) 66, (byte) 32, (byte) 88, (byte) 89, (byte) 90, (byte) 32, (byte) 7, (byte) -27, (byte) 0, (byte) 10, (byte) 0, (byte) 4, (byte) 0, (byte) 12, (byte) 0, (byte) 27, (byte) 0, (byte) 19, (byte) 97, (byte) 99, (byte) 115, (byte) 112, (byte) 65, (byte) 80, (byte) 80, (byte) 76, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -10, (byte) -42, (byte) 0, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -45, (byte) 45, (byte) 108, (byte) 99, (byte) 109, (byte) 115, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 13, (byte) 100, (byte) 101, (byte) 115, (byte) 99, (byte) 0, (byte) 0, (byte) 1, (byte) 32, (byte) 0, (byte) 0, (byte) 0, (byte) 64, (byte) 99, (byte) 112, (byte) 114, (byte) 116, (byte) 0, (byte) 0, (byte) 1, (byte) 96, (byte) 0, (byte) 0, (byte) 0, (byte) 54, (byte) 119, (byte) 116, (byte) 112, (byte) 116, (byte) 0, (byte) 0, (byte) 1, (byte) -104, (byte) 0, (byte) 0, (byte) 0, (byte) 20, (byte) 99, (byte) 104, (byte) 97, (byte) 100, (byte) 0, (byte) 0, (byte) 1, (byte) -84, (byte) 0, (byte) 0, (byte) 0, (byte) 44, (byte) 114, (byte) 88, (byte) 89, (byte) 90, (byte) 0, (byte) 0, (byte) 1, (byte) -40, (byte) 0, (byte) 0, (byte) 0, (byte) 20, (byte) 98, (byte) 88, (byte) 89, (byte) 90, (byte) 0, (byte) 0, (byte) 1, (byte) -20, (byte) 0, (byte) 0, (byte) 0, (byte) 20, (byte) 103, (byte) 88, (byte) 89, (byte) 90, (byte) 0, (byte) 0, (byte) 2, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 20, (byte) 114, (byte) 84, (byte) 82, (byte) 67, (byte) 0, (byte) 0, (byte) 2, (byte) 20, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) 103, (byte) 84, (byte) 82, (byte) 67, (byte) 0, (byte) 0, (byte) 2, (byte) 20, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) 98, (byte) 84, (byte) 82, (byte) 67, (byte) 0, (byte) 0, (byte) 2, (byte) 20, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) 99, (byte) 104, (byte) 114, (byte) 109, (byte) 0, (byte) 0, (byte) 2, (byte) 52, (byte) 0, (byte) 0, (byte) 0, (byte) 36, (byte) 100, (byte) 109, (byte) 110, (byte) 100, (byte) 0, (byte) 0, (byte) 2, (byte) 88, (byte) 0, (byte) 0, (byte) 0, (byte) 36, (byte) 100, (byte) 109, (byte) 100, (byte) 100, (byte) 0, (byte) 0, (byte) 2, (byte) 124, (byte) 0, (byte) 0, (byte) 0, (byte) 36, (byte) 109, (byte) 108, (byte) 117, (byte) 99, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 12, (byte) 101, (byte) 110, (byte) 85, (byte) 83, (byte) 0, (byte) 0, (byte) 0, (byte) 36, (byte) 0, (byte) 0, (byte) 0, (byte) 28, (byte) 0, (byte) 71, (byte) 0, (byte) 73, (byte) 0, (byte) 77, (byte) 0, (byte) 80, (byte) 0, (byte) 32, (byte) 0, (byte) 98, (byte) 0, (byte) 117, (byte) 0, (byte) 105, (byte) 0, (byte) 108, (byte) 0, (byte) 116, (byte) 0, (byte) 45, (byte) 0, (byte) 105, (byte) 0, (byte) 110, (byte) 0, (byte) 32, (byte) 0, (byte) 115, (byte) 0, (byte) 82, (byte) 0, (byte) 71, (byte) 0, (byte) 66, (byte) 109, (byte) 108, (byte) 117, (byte) 99, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 12, (byte) 101, (byte) 110, (byte) 85, (byte) 83, (byte) 0, (byte) 0, (byte) 0, (byte) 26, (byte) 0, (byte) 0, (byte) 0, (byte) 28, (byte) 0, (byte) 80, (byte) 0, (byte) 117, (byte) 0, (byte) 98, (byte) 0, (byte) 108, (byte) 0, (byte) 105, (byte) 0, (byte) 99, (byte) 0, (byte) 32, (byte) 0, (byte) 68, (byte) 0, (byte) 111, (byte) 0, (byte) 109, (byte) 0, (byte) 97, (byte) 0, (byte) 105, (byte) 0, (byte) 110, (byte) 0, (byte) 0, (byte) 88, (byte) 89, (byte) 90, (byte) 32, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -10, (byte) -42, (byte) 0, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -45, (byte) 45, (byte) 115, (byte) 102, (byte) 51, (byte) 50, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 12, (byte) 66, (byte) 0, (byte) 0, (byte) 5, (byte) -34, (byte) -1, (byte) -1, (byte) -13, (byte) 37, (byte) 0, (byte) 0, (byte) 7, (byte) -109, (byte) 0, (byte) 0, (byte) -3, (byte) -112, (byte) -1, (byte) -1, (byte) -5, (byte) -95, (byte) -1, (byte) -1, (byte) -3, (byte) -94, (byte) 0, (byte) 0, (byte) 3, (byte) -36, (byte) 0, (byte) 0, (byte) -64, (byte) 110, (byte) 88, (byte) 89, (byte) 90, (byte) 32, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 111, (byte) -96, (byte) 0, (byte) 0, (byte) 56, (byte) -11, (byte) 0, (byte) 0, (byte) 3, (byte) -112, (byte) 88, (byte) 89, (byte) 90, (byte) 32, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 36, (byte) -97, (byte) 0, (byte) 0, (byte) 15, (byte) -124, (byte) 0, (byte) 0, (byte) -74, (byte) -60, (byte) 88, (byte) 89, (byte) 90, (byte) 32, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 98, (byte) -105, (byte) 0, (byte) 0, (byte) -73, (byte) -121, (byte) 0, (byte) 0, (byte) 24, (byte) -39, (byte) 112, (byte) 97, (byte) 114, (byte) 97, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 3, (byte) 0, (byte) 0, (byte) 0, (byte) 2, (byte) 102, (byte) 102, (byte) 0, (byte) 0, (byte) -14, (byte) -89, (byte) 0, (byte) 0, (byte) 13, (byte) 89, (byte) 0, (byte) 0, (byte) 19, (byte) -48, (byte) 0, (byte) 0, (byte) 10, (byte) 91, (byte) 99, (byte) 104, (byte) 114, (byte) 109, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 3, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -93, (byte) -41, (byte) 0, (byte) 0, (byte) 84, (byte) 124, (byte) 0, (byte) 0, (byte) 76, (byte) -51, (byte) 0, (byte) 0, (byte) -103, (byte) -102, (byte) 0, (byte) 0, (byte) 38, (byte) 103, (byte) 0, (byte) 0, (byte) 15, (byte) 92, (byte) 109, (byte) 108, (byte) 117, (byte) 99, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 12, (byte) 101, (byte) 110, (byte) 85, (byte) 83, (byte) 0, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 0, (byte) 28, (byte) 0, (byte) 71, (byte) 0, (byte) 73, (byte) 0, (byte) 77, (byte) 0, (byte) 80, (byte) 109, (byte) 108, (byte) 117, (byte) 99, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 12, (byte) 101, (byte) 110, (byte) 85, (byte) 83, (byte) 0, (byte) 0, (byte) 0, (byte) 8, (byte) 0, (byte) 0, (byte) 0, (byte) 28, (byte) 0, (byte) 115, (byte) 0, (byte) 82, (byte) 0, (byte) 71, (byte) 0, (byte) 66, (byte) -1, (byte) -37, (byte) 0, (byte) 67, (byte) 0, (byte) 16, (byte) 11, (byte) 12, (byte) 14, (byte) 12, (byte) 10, (byte) 16, (byte) 14, (byte) 13, (byte) 14, (byte) 18, (byte) 17, (byte) 16, (byte) 19, (byte) 24, (byte) 40, (byte) 26, (byte) 24, (byte) 22, (byte) 22, (byte) 24, (byte) 49, (byte) 35, (byte) 37, (byte) 29, (byte) 40, (byte) 58, (byte) 51, (byte) 61, (byte) 60, (byte) 57, (byte) 51, (byte) 56, (byte) 55, (byte) 64, (byte) 72, (byte) 92, (byte) 78, (byte) 64, (byte) 68, (byte) 87, (byte) 69, (byte) 55, (byte) 56, (byte) 80, (byte) 109, (byte) 81, (byte) 87, (byte) 95, (byte) 98, (byte) 103, (byte) 104, (byte) 103, (byte) 62, (byte) 77, (byte) 113, (byte) 121, (byte) 112, (byte) 100, (byte) 120, (byte) 92, (byte) 101, (byte) 103, (byte) 99, (byte) -1, (byte) -37, (byte) 0, (byte) 67, (byte) 1, (byte) 17, (byte) 18, (byte) 18, (byte) 24, (byte) 21, (byte) 24, (byte) 47, (byte) 26, (byte) 26, (byte) 47, (byte) 99, (byte) 66, (byte) 56, (byte) 66, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) 99, (byte) -1, (byte) -62, (byte) 0, (byte) 17, (byte) 8, (byte) 0, (byte) 16, (byte) 0, (byte) 16, (byte) 3, (byte) 1, (byte) 17, (byte) 0, (byte) 2, (byte) 17, (byte) 1, (byte) 3, (byte) 17, (byte) 1, (byte) -1, (byte) -60, (byte) 0, (byte) 22, (byte) 0, (byte) 1, (byte) 1, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 3, (byte) 5, (byte) -1, (byte) -60, (byte) 0, (byte) 20, (byte) 1, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -1, (byte) -38, (byte) 0, (byte) 12, (byte) 3, (byte) 1, (byte) 0, (byte) 2, (byte) 16, (byte) 3, (byte) 16, (byte) 0, (byte) 0, (byte) 1, (byte) -46, (byte) 4, (byte) -127, (byte) -1, (byte) -60, (byte) 0, (byte) 23, (byte) 16, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 3, (byte) 1, (byte) 2, (byte) 18, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 1, (byte) 0, (byte) 1, (byte) 5, (byte) 2, (byte) 100, (byte) -99, (byte) -118, (byte) 78, (byte) -44, (byte) -18, (byte) -100, (byte) -114, (byte) -27, (byte) -1, (byte) 0, (byte) -1, (byte) -60, (byte) 0, (byte) 20, (byte) 17, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 3, (byte) 1, (byte) 1, (byte) 63, (byte) 1, (byte) 31, (byte) -1, (byte) -60, (byte) 0, (byte) 20, (byte) 17, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 2, (byte) 1, (byte) 1, (byte) 63, (byte) 1, (byte) 31, (byte) -1, (byte) -60, (byte) 0, (byte) 31, (byte) 16, (byte) 0, (byte) 1, (byte) 1, (byte) 9, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0, (byte) 2, (byte) 17, (byte) 18, (byte) 33, (byte) 49, (byte) 81, (byte) 113, (byte) -111, (byte) -47, (byte) 3, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 1, (byte) 0, (byte) 6, (byte) 63, (byte) 2, (byte) 30, (byte) 111, (byte) 55, (byte) 107, (byte) 8, (byte) -80, (byte) -13, (byte) 118, (byte) 112, (byte) -88, (byte) 97, (byte) 32, (byte) 79, (byte) 125, (byte) 84, (byte) 48, (byte) -128, (byte) 103, (byte) -82, (byte) 47, (byte) -1, (byte) -60, (byte) 0, (byte) 28, (byte) 16, (byte) 1, (byte) 0, (byte) 2, (byte) 1, (byte) 5, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0, (byte) 17, (byte) 33, (byte) 49, (byte) 65, (byte) 81, (byte) 113, (byte) -127, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 1, (byte) 0, (byte) 1, (byte) 63, (byte) 33, (byte) 50, (byte) -128, (byte) -43, (byte) 26, (byte) -84, (byte) -73, (byte) -18, (byte) 56, (byte) 104, (byte) 106, (byte) -83, (byte) -34, (byte) 27, (byte) -9, (byte) 26, (byte) 113, (byte) -125, (byte) -59, (byte) 65, (byte) 78, (byte) 112, (byte) 120, (byte) -88, (byte) -1, (byte) -38, (byte) 0, (byte) 12, (byte) 3, (byte) 1, (byte) 0, (byte) 2, (byte) 0, (byte) 3, (byte) 0, (byte) 0, (byte) 0, (byte) 16, (byte) 0, (byte) 15, (byte) -1, (byte) -60, (byte) 0, (byte) 20, (byte) 17, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 3, (byte) 1, (byte) 1, (byte) 63, (byte) 16, (byte) 31, (byte) -1, (byte) -60, (byte) 0, (byte) 20, (byte) 17, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 32, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 2, (byte) 1, (byte) 1, (byte) 63, (byte) 16, (byte) 31, (byte) -1, (byte) -60, (byte) 0, (byte) 25, (byte) 16, (byte) 1, (byte) 1, (byte) 0, (byte) 3, (byte) 1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 17, (byte) 0, (byte) 33, (byte) 49, (byte) 65, (byte) -1, (byte) -38, (byte) 0, (byte) 8, (byte) 1, (byte) 1, (byte) 0, (byte) 1, (byte) 63, (byte) 16, (byte) -107, (byte) 3, (byte) 101, (byte) -86, (byte) 14, (byte) -55, (byte) 65, (byte) -18, (byte) 74, (byte) -95, (byte) -78, (byte) -43, (byte) 15, (byte) 109, (byte) -119, (byte) -9, (byte) 27, (byte) -42, (byte) -76, (byte) -70, (byte) 80, (byte) 69, (byte) -91, (byte) -27, (byte) 115, (byte) -61, (byte) 27, (byte) -62, (byte) -108, (byte) -70, (byte) 20, (byte) 1, (byte) -95, (byte) -27, (byte) 115, (byte) -41, (byte) 63, (byte) -1, (byte) -39};
    private static PGPUserAttributeSubpacketVector attribute;
    private static PGPUserAttributeSubpacketVector invalidAttribute;

    static {
        PGPUserAttributeSubpacketVectorGenerator attrGen = new PGPUserAttributeSubpacketVectorGenerator();
        attrGen.setImageAttribute(ImageAttribute.JPEG, image);
        attribute = attrGen.generate();

        byte[] modifiedImage = new byte[image.length];
        System.arraycopy(image, 0, modifiedImage, 0, image.length);
        modifiedImage[0] = 25; // modify image

        attrGen = new PGPUserAttributeSubpacketVectorGenerator();
        attrGen.setImageAttribute(ImageAttribute.JPEG, modifiedImage);
        invalidAttribute = attrGen.generate();
    }

    @Test
    public void createAndVerifyUserAttributeCertification() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPSecretKey secretKey = secretKeys.getSecretKey();
        PGPPublicKey publicKey = secretKey.getPublicKey();
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance()
                        .getPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()));
        generator.init(SignatureType.CASUAL_CERTIFICATION.getCode(), privateKey);

        PGPSignature signature = generator.generateCertification(attribute, publicKey);
        publicKey = PGPPublicKey.addCertification(publicKey, attribute, signature);
        SignatureVerifier.verifyUserAttributesCertification(attribute, signature, publicKey, PGPainless.getPolicy(), new Date());

        PGPPublicKey finalPublicKey = publicKey;
        assertThrows(SignatureValidationException.class, () -> SignatureVerifier.verifyUserAttributesCertification(invalidAttribute, signature, finalPublicKey, PGPainless.getPolicy(), new Date()));
    }

    @Test
    public void createAndVerifyUserAttributeRevocation() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        PGPSecretKey secretKey = secretKeys.getSecretKey();
        PGPPublicKey publicKey = secretKey.getPublicKey();
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance()
                        .getPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()));
        generator.init(SignatureType.CERTIFICATION_REVOCATION.getCode(), privateKey);

        PGPSignature signature = generator.generateCertification(attribute, publicKey);
        publicKey = PGPPublicKey.addCertification(publicKey, attribute, signature);
        SignatureVerifier.verifyUserAttributesRevocation(attribute, signature, publicKey, PGPainless.getPolicy(), new Date());
        PGPPublicKey finalPublicKey = publicKey;
        assertThrows(SignatureValidationException.class, () -> SignatureVerifier.verifyUserAttributesCertification(invalidAttribute, signature, finalPublicKey, PGPainless.getPolicy(), new Date()));
    }
}
