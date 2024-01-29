/*
 * Copyright 2024 Gonçalo Frade
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

import Foundation

enum DIDCommError: LocalizedError {
    case invalidDID(String)
    case expectedDIDFragment(String)
    case unsupportedKey(String, supported: [String])
    case invalidKeySize(Int)
    case invalidBase64URLKey
    case invalidSecretFormatForMethodType(methodType: String, format: String, expected: String)
    case verificationMethodNotFoundForId(String)
    case unsupportedVerificationMethodTypeException(String)
    case secretNotFound(String)
    case secretsNotFound([String])
    case unexpectedCurve(id: String, curve: String, expected: String)
    case unsupportedCryptoAlgorithme(algorithm: String, encoding: String)
    case malformedMessage(String)
    case skidMissing
    case somethingWentWrong
}
