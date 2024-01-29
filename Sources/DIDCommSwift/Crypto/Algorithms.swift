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

public enum CryptAlg {
    case authCryptAlg(AuthCryptAlg)
    case anonCryptAlg(AnonCryptAlg)
    
    var authCrypt: AuthCryptAlg? {
        switch self {
        case .authCryptAlg(let value):
            return value
        default:
            return nil
        }
    }
    
    var anonCrypt: AnonCryptAlg? {
        switch self {
        case .anonCryptAlg(let value):
            return value
        default:
            return nil
        }
    }
}

/// Algorithms for anonymous encryption.
public enum AnonCryptAlg: String {
    /// a256CbcHs512EcdhEsA256kw: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    case a256CbcHs512EcdhEsA256kw

    /// xc20pEcdhEsA256kw: XChaCha20Poly1305 with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    case xc20pEcdhEsA256kw

    /// a256GcmEcdhEsA256kw: AES256-GCM with a 256 bit key content encryption,
    /// ECDH-ES key agreement with A256KW key wrapping
    case a256GcmEcdhEsA256kw
}

/// Algorithms for authentication encryption.
public enum AuthCryptAlg: String {
    /// a256CbcHs512Ecdh1puA256kw: AES256-CBC + HMAC-SHA512 with a 512 bit key content encryption,
    /// ECDH-1PU key agreement with A256KW key wrapping
    case a256CbcHs512Ecdh1puA256kw
}

/// Algorithms for signature (non-repudiation)
public enum SignAlg {
    /// elliptic curve digital signature with edwards curves Ed25519 and SHA-512
    case ed25519

    /// elliptic curve digital signature with NIST p-256 curve and SHA-256
    case es256

    /// elliptic curve digital signature with Secp256k1 keys
    case es256k
}
