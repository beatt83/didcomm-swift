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

/// Enumerates various errors that can occur within the DIDComm messaging framework, providing specific details for troubleshooting.
enum DIDCommError: LocalizedError {
    /// Expected a DID fragment but received a different format.
    case expectedDIDFragment(String)
    
    /// The data type of an attachment does not match any of the expected DIDComm data types.
    case invalidAttachmentDataType
    
    /// The provided key is not valid Base64URL format.
    case invalidBase64URLKey
    
    /// The provided DID is not valid according to DID standards.
    case invalidDID(String)
    
    /// The size of the provided key is not valid for the expected cryptographic operations.
    case invalidKeySize(Int)
    
    /// The format of a secret does not match the expected format for the provided method type.
    case invalidSecretFormatForMethodType(methodType: String, format: String, expected: String)
    
    /// The message structure is malformed and cannot be processed.
    case malformedMessage(String)
    
    /// The 'to' field is missing in a message that requires it for processing.
    case missingTo
    
    /// The 'from' field is missing in a message that requires it for processing.
    case missingFrom
    
    /// The body of the message is missing.
    case missingBody
    
    /// An expected attachment is missing from the message.
    case missingAttachment
    
    /// A required URI is missing.
    case missingUri
    
    /// The message is not of a forward message type but was expected to be.
    case notForwardMessageType
    
    /// The service type is not recognized as a DIDComm service type.
    case notDidCommServiceType
    
    /// A verification method specified in the message could not be found for the given identifier.
    case verificationMethodNotFoundForId(String)
    
    /// The provided key or secret could not be found.
    case secretNotFound(String)
    
    /// Multiple secrets specified could not be found.
    case secretsNotFound([String])
    
    /// The curve specified is unexpected for the given cryptographic operation.
    case unexpectedCurve(id: String?, curve: String?, expected: [String])
    
    /// The cryptographic algorithm specified is not supported, possibly including an unsupported encoding.
    case unsupportedCryptoAlgorithme(algorithm: String, encoding: String)
    
    /// Indicates that the provided key is unsupported for the operation being attempted.
    case unsupportedKey(String, supported: [String])
    
    /// The type of verification method provided is unsupported for the required operation.
    case unsupportedVerificationMethodTypeException(String)
    
    /// The provided key is missing a `skid` (Secret Key Identifier).
    case skidMissing
    
    /// Required parameters for an operation are missing or not supported.
    case unsupportedParams(required: [String])
    
    /// Unable to resolve the specified DID.
    case unableToResolveDID(String)
    
    /// A generic error for unexpected or miscellaneous issues.
    case somethingWentWrong
    
    var errorDescription: String? {
        switch self {
        case .expectedDIDFragment(let fragment):
            return "Expected a DID fragment but received: \(fragment)."
        case .invalidAttachmentDataType:
            return "The attachment data type is invalid or unsupported."
        case .invalidBase64URLKey:
            return "The provided key is not a valid Base64URL format."
        case .invalidDID(let did):
            return "The DID '\(did)' is invalid or malformed."
        case .invalidKeySize(let size):
            return "The key size \(size) is invalid for the expected cryptographic operation."
        case .invalidSecretFormatForMethodType(let methodType, let format, let expected):
            return "Invalid secret format for method type '\(methodType)'. Format received: '\(format)', expected: '\(expected)'."
        case .malformedMessage(let message):
            return "The message is malformed: \(message)."
        case .missingTo:
            return "The 'to' field is missing in the message."
        case .missingFrom:
            return "The 'from' field is missing in the message."
        case .missingBody:
            return "The body of the message is missing."
        case .missingAttachment:
            return "An expected attachment is missing from the message."
        case .missingUri:
            return "A required URI is missing from the message or document."
        case .notForwardMessageType:
            return "The message is not of a 'forward' message type as expected."
        case .notDidCommServiceType:
            return "The service type is not recognized as a valid DIDComm service type."
        case .verificationMethodNotFoundForId(let id):
            return "A verification method could not be found for the identifier: \(id)."
        case .unsupportedVerificationMethodTypeException(let type):
            return "The verification method type '\(type)' is unsupported."
        case .secretNotFound(let id):
            return "The secret for identifier '\(id)' could not be found."
        case .secretsNotFound(let ids):
            return "The secrets for identifiers \(ids) could not be found."
        case .unexpectedCurve(let id, let curve, let expected):
            return "Unexpected curve for identifier \(id ?? "unknown"). Curve: \(curve ?? "unknown"), expected: \(expected)."
        case .unsupportedCryptoAlgorithme(let algorithm, let encoding):
            return "Unsupported cryptographic algorithm '\(algorithm)' with encoding '\(encoding)'."
        case .unsupportedKey(let key, let supported):
            return "The key '\(key)' is unsupported. Supported keys are: \(supported.joined(separator: ", "))."
        case .skidMissing:
            return "The 'skid' (Secret Key Identifier) is missing."
        case .unsupportedParams(let required):
            return "Unsupported parameters. Required: \(required)."
        case .unableToResolveDID(let did):
            return "Unable to resolve the DID: \(did)."
        case .somethingWentWrong:
            return "An unspecified error occurred."
        }
    }
}
