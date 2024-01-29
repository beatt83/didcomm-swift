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

/// Unpack Parameters.
public struct UnpackParams {
    public let packedMessage: String
    public let expectDecryptByAllKeys: Bool
    public let unwrapReWrappingForward: Bool
    public let didResolver: DIDResolver?
    public let secretResolver: SecretResolver?

    public init(
        packedMessage: String,
        expectDecryptByAllKeys: Bool = false,
        unwrapReWrappingForward: Bool = true,
        didResolver: DIDResolver? = nil,
        secretResolver: SecretResolver? = nil
    ) {
        self.packedMessage = packedMessage
        self.expectDecryptByAllKeys = expectDecryptByAllKeys
        self.unwrapReWrappingForward = unwrapReWrappingForward
        self.didResolver = didResolver
        self.secretResolver = secretResolver
    }
}
