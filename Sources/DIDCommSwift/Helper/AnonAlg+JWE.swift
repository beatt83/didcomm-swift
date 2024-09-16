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
import JSONWebAlgorithms

extension AnonymousEncryptionAlgorithms {
    var jweReference: (ContentEncryptionAlgorithm, KeyManagementAlgorithm) {
        switch self {
        case .a256CBCHS512:
            return (ContentEncryptionAlgorithm.a256CBCHS512, KeyManagementAlgorithm.ecdhESA256KW)
        case .a256GCM:
            return (ContentEncryptionAlgorithm.a256GCM, KeyManagementAlgorithm.ecdhESA256KW)
        case .XC20P:
            return (ContentEncryptionAlgorithm.xC20P, KeyManagementAlgorithm.ecdhESA256KW)
        }
    }
    
    static func fromReference(keyAlg: KeyManagementAlgorithm, encAlg: ContentEncryptionAlgorithm) throws -> AnonymousEncryptionAlgorithms {
        switch (keyAlg, encAlg) {
        case (.ecdhESA256KW, .a256CBCHS512):
            return .a256CBCHS512
        case (.ecdhESA256KW, .a256GCM):
            return .a256GCM
        case (.ecdhESA256KW, .xC20P):
            return .XC20P
        default:
            throw DIDCommError.unsupportedCryptoAlgorithme(algorithm: keyAlg.rawValue, encoding: encAlg.rawValue)
        }
    }
}
