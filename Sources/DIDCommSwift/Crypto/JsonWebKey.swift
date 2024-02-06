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
import JSONWebKey

struct JsonWebKey: Key {
    let id: String
    let jwk: JSONWebKey.JWK
    let curve: String
    
    init(id: String, jwk: JSONWebKey.JWK, curve: String) {
        self.id = id
        self.jwk = jwk
        self.curve = curve
    }
    
    init(id: String, materialValue: Data) throws {
        self.id = id
        var jwk = try JSONDecoder().decode(JSONWebKey.JWK.self, from: materialValue)
        jwk.keyID = id
        self.jwk = jwk
        self.curve = jwk.curve?.rawValue ?? ""
    }
}
