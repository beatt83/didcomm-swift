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

extension AuthCryptAlg {
    var jweReference: (ContentEncryptionAlgorithm, KeyManagementAlgorithm) {
        switch self {
        case .a256CbcHs512Ecdh1puA256kw:
            return (.a256CBCHS512, .ecdh1PUA256KW)
        }
    }
    
    static func fromReference(keyAlg: KeyManagementAlgorithm, encAlg: ContentEncryptionAlgorithm) throws -> AuthCryptAlg {
        switch (keyAlg, encAlg) {
        case (.ecdh1PUA256KW, .a256CBCHS512):
            return .a256CbcHs512Ecdh1puA256kw
        default:
            throw DIDCommError.unsupportedCryptoAlgorithme(algorithm: keyAlg.rawValue, encoding: encAlg.rawValue)
        }
    }
}
