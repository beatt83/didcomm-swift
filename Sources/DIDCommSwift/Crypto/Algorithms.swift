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

/// Enumerates the algorithms available for anonymous encryption within the DIDCommV2 framework.
///
/// These algorithms are used for encrypting messages without revealing the sender's identity to the recipient.
///
/// - Note: The XC20P algorithm is listed for completeness but is currently not supported.
public enum AnonymousEncryptionAlgorithms: String {
    /// AES encryption using CBC mode and HMAC SHA-512 for integrity, with a 256-bit key.
    case a256CBCHS512 = "A256CBC-HS512"
    
    /// AES encryption with Galois/Counter Mode (GCM) using a 256-bit key.
    case a256GCM = "A256GCM"
    
    /// XChaCha20-Poly1305, a combination of the XChaCha20 stream cipher and the Poly1305 MAC.
    /// Currently not supported in this implementation.
    case XC20P = "XC20P"
}

/// Enumerates the algorithms available for authenticated encryption within the DIDCommV2 framework.
///
/// Authenticated encryption provides confidentiality, integrity, and authenticity assurances on the encrypted data.
public enum AuthenticatedEncryptionAlg: String {
    /// AES encryption using CBC mode and HMAC SHA-512 for integrity, with a 256-bit key.
    /// This algorithm ensures that the data is encrypted and the sender is authenticated to the recipient.
    case a256CBCHS512 = "A256CBC-HS512"
}

/// Enumerates the algorithms available for digital signatures within the DIDCommV2 framework.
///
/// These algorithms are critical for providing non-repudiation, allowing the sender of a message
/// to be authenticated via a digital signature verified by the recipient, ensuring the authenticity and integrity of the sender.
public enum SignAlg {
    /// Elliptic Curve Digital Signature Algorithm using Edwards curves Ed25519 and SHA-512 for hashing.
    /// Known for its high security and efficiency, Ed25519 is suitable for high-security applications requiring efficient verification.
    case ed25519

    /// Elliptic Curve Digital Signature Algorithm with NIST P-256 curve and SHA-256 for hashing.
    /// ES256 offers a balance of security and performance, widely adopted across various industries for digital signatures.
    case es256
    
    /// Elliptic Curve Digital Signature Algorithm with NIST P-384 curve and SHA-384 for hashing.
    /// ES384 provides enhanced security over ES256, making it suitable for applications requiring higher security assurances.
    case es384
    
    /// Elliptic Curve Digital Signature Algorithm with NIST P-521 curve and SHA-512 for hashing.
    /// ES512 offers the highest level of security among the ECDSA options in this enum, recommended for maximum security requirements.
    case es512

    /// Elliptic Curve Digital Signature Algorithm with Secp256k1 keys.
    /// ES256K is predominantly used in blockchain applications, offering robust security features tailored for digital transactions.
    case es256k
}
