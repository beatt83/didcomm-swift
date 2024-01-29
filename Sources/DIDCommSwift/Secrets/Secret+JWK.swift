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

import DIDCore
import Foundation

extension Secret {
    
    init(from: JWK) throws {
        self.kid = from.kid ?? ""
        self.type = .authentication(.jsonWebKey2020)
        self.verificationMaterial = .init(
            format: .jwk,
            value: try JSONEncoder.DIDCoreEncoder().encode(from)
        )
    }
}

extension JWK {
    
    init(from: Secret) throws {
        self = try JSONDecoder().decode(JWK.self, from: from.verificationMaterial.value)
    }
}
