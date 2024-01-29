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

@testable import DIDCommSwift
import DIDCore
import Foundation

class CharlieSecretResolverMock: SecretResolver {
    let secrets: [Secret] = [
        Secret(kid: "did:example:charlie#key-x25519-1",
              type: .agreement(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"OKP",
                   "d":"Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                   "crv":"X25519",
                   "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                }
                """.data(using: .utf8)!)),

        Secret(kid: "did:example:charlie#key-x25519-3",
              type: .agreement(.jsonWebKey2020),
              verificationMaterial: VerificationMaterial(format: .jwk, value: """
                {
                   "kty":"OKP",
                   "d":"Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                   "crv":"X25519",
                   "x":"nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw"
                }
                """.data(using: .utf8)!))
    ]

    
    lazy var secretResolver = SecretResolverInMemory(secrets: secrets)
    
    func findKey(kid: String) async throws -> Secret? {
        try await secretResolver.findKey(kid: kid)
    }
    
    func findKeys(kids: Set<String>) async throws -> Set<String> {
        try await secretResolver.findKeys(kids: kids)
    }
}
