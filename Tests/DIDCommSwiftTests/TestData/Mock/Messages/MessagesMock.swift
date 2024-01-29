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
import Foundation

extension Message {
    
    static var plainTextMessage = Message.testable(
        typ: .plainText,
        from: aliceDID,
        to: [bobDID]
    )
    
    static var encryptedTextMessage = Message.testable(
        typ: .encrypted
    )
    
    static var plainTextMessageFromPriorMinimal = Message.testable(
        from: aliceDID,
        to: [bobDID],
        createdTime: Date(timeIntervalSince1970: 1516269022),
        expiresTime: Date(timeIntervalSince1970: 1516385931),
        fromPrior: .init(iss: aliceDID, sub: charlieDID)
    )
    
    static var plainTextMessageFromPrior = Message.testable(
        from: charlieDID,
        to: [bobDID],
        createdTime: Date(timeIntervalSince1970: 1516269022),
        expiresTime: Date(timeIntervalSince1970: 1516385931),
        fromPrior: .init(
            iss: aliceDID,
            sub: charlieDID,
            aud: "123",
            jti: "dfg"
        )
    )
    
    static func testable(
        id: String = "1234567890",
        body: Data? = "{\"messagespecificattribute\":\"and its value\"}".data(using: .utf8)!,
        type: String = "http://example.com/protocols/lets_do_lunch/1.0/proposal",
        typ: Typ = .plainText,
        from: String? = nil,
        to: [String]? = nil,
        createdTime: Date? = .init(timeIntervalSince1970: 1516269022),
        expiresTime: Date? = .init(timeIntervalSince1970: 1516385931),
        fromPrior: FromPrior? = nil,
        fromPriorJwt: String? = nil
    ) -> Message {
        .init(
            id: id,
            body: body,
            type: type,
            typ: typ,
            from: from,
            to: to,
            createdTime: createdTime,
            expiresTime: expiresTime,
            fromPrior: fromPrior,
            fromPriorJwt: fromPriorJwt,
            attachments: nil,
            pleaseAck: nil,
            ack: nil,
            thid: nil,
            pthid: nil,
            customHeaders: nil
        )
    }
}

let bob_damage_message = """
{
   "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
   "recipients":[
      {
         "encrypted_key":"3n1olyBR3nY7ZGAprOx-b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1a",
         "header":{
            "kid":"did:example:bob#key-x25519-1"
         }
      },
      {
         "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
         "header":{
            "kid":"did:example:bob#key-x25519-2"
         }
      },
      {
         "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
         "header":{
            "kid":"did:example:bob#key-x25519-3"
         }
      }
   ],
   "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
   "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_without_recipients = """
{
   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
   "tag":"t8ioLvZhsCp7A93jvdf3wA",
   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_without_protected_header = """
{
   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
   "recipients":[
      {
         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
         "header":{
            "kid":"did:example:bob#key-p256-1"
         }
      },
      {
         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
         "header":{
            "kid":"did:example:bob#key-p256-2"
         }
      }
   ],
   "tag":"t8ioLvZhsCp7A93jvdf3wA",
   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_without_cipher = """
{
   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
   "recipients":[
      {
         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
         "header":{
            "kid":"did:example:bob#key-p256-1"
         }
      },
      {
         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
         "header":{
            "kid":"did:example:bob#key-p256-2"
         }
      }
   ],
   "tag":"t8ioLvZhsCp7A93jvdf3wA",
   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_without_tag = """
{
   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
   "recipients":[
      {
         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
         "header":{
            "kid":"did:example:bob#key-p256-1"
         }
      },
      {
         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
         "header":{
            "kid":"did:example:bob#key-p256-2"
         }
      }
   ],
   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_without_iv = """
{
   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
   "recipients":[
      {
         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
         "header":{
            "kid":"did:example:bob#key-p256-1"
         }
      },
      {
         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
         "header":{
            "kid":"did:example:bob#key-p256-2"
         }
      }
   ],
   "tag":"t8ioLvZhsCp7A93jvdf3wA"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_unsupported_alg = """
{
   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NUtXIn0=",
   "recipients":[
      {
         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
         "header":{
            "kid":"did:example:bob#key-p256-1"
         }
      },
      {
         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
         "header":{
            "kid":"did:example:bob#key-p256-2"
         }
      }
   ],
   "tag":"t8ioLvZhsCp7A93jvdf3wA",
   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
""".replacingWhiteSpacesAndNewLines()

let bob_message_unssuported_enc_alg = """
{
   "ciphertext":"912eTUDRKTzhUUqxosPogT1bs9w9wv4s4HmoWkaeU9Uj92V4ENpk-_ZPNSvPyXYLfFj0nc9V2-ux5jq8hqUd17WJpXEM1ReMUjtnTqeUzVa7_xtfkbfhaOZdL8OfgNquPDH1bYcBshN9O9lMT0V52gmGaAB45k4I2PNHcc0A5XWzditCYi8wOkPDm5A7pA39Au5uUNiFQjRYDrz1YvJwV9cdca54vYsBfV1q4c8ncQsv5tNnFYQ1s4rAG7RbyWdAjkC89kE_hIoRRkWZhFyNSfdvRtlUJDlM19uml7lwBWWPnqkmQ3ubiBGmVct3pjrcDvjissOw8Dwkn4E1V1gafec-jDBy4Rndai_RdGjnXjMJs7nRv3Ot",
   "protected":"eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJFczdpUDNFaExDSGxBclAwS2NZRmNxRXlCYXByMks2WU9BOVc4ZU84YXU4IiwieSI6Ik42QWw3RVR3Q2RwQzZOamRlY3IyS1hBZzFVZVp5X3VmSFJRS3A5RzZLR2sifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQSDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwMiIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0=",
   "recipients":[
      {
         "encrypted_key":"G-UFZ1ebuhlWZTrMj214YcEvHl6hyfsFtWv4hj-NPNi9gpi99rRs3Q",
         "header":{
            "kid":"did:example:bob#key-p256-1"
         }
      },
      {
         "encrypted_key":"gVdbFdXAxEgrtj9Uw2xiEucQukpiAOA3Jp7Ecmb6L7G5c3IIcAAHgQ",
         "header":{
            "kid":"did:example:bob#key-p256-2"
         }
      }
   ],
   "tag":"t8ioLvZhsCp7A93jvdf3wA",
   "iv":"JrIpD5q5ifMq6PT06pYh6QhCQ6LgnGpF"
}
""".replacingWhiteSpacesAndNewLines()

let bob_anon_message_key_is_invalid = """
{
   "ciphertext":"KWS7gJU7TbyJlcT9dPkCw-ohNigGaHSukR9MUqFM0THbCTCNkY-g5tahBFyszlKIKXs7qOtqzYyWbPou2q77XlAeYs93IhF6NvaIjyNqYklvj-OtJt9W2Pj5CLOMdsR0C30wchGoXd6wEQZY4ttbzpxYznqPmJ0b9KW6ZP-l4_DSRYe9B-1oSWMNmqMPwluKbtguC-riy356Xbu2C9ShfWmpmjz1HyJWQhZfczuwkWWlE63g26FMskIZZd_jGpEhPFHKUXCFwbuiw_Iy3R0BIzmXXdK_w7PZMMPbaxssl2UeJmLQgCAP8j8TukxV96EKa6rGgULvlo7qibjJqsS5j03bnbxkuxwbfyu3OxwgVzFWlyHbUH6p",
   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkpIanNtSVJaQWFCMHpSR193TlhMVjJyUGdnRjAwaGRIYlc1cmo4ZzBJMjQifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIwUCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
   "recipients":[
      {
         "encrypted_key":"3n1olyBR3nY7ZGAprOx-\\b7wYAKza6cvOYjNwVg3miTnbLwPP_FmE1A",
         "header":{
            "kid":"did:example:bob#key-x25519-1"
         }
      },
      {
         "encrypted_key":"j5eSzn3kCrIkhQAWPnEwrFPMW6hG0zF_y37gUvvc5gvlzsuNX4hXrQ",
         "header":{
            "kid":"did:example:bob#key-x25519-2"
         }
      },
      {
         "encrypted_key":"TEWlqlq-ao7Lbynf0oZYhxs7ZB39SUWBCK4qjqQqfeItfwmNyDm73A",
         "header":{
            "kid":"did:example:bob#key-x25519-3"
         }
      }
   ],
   "tag":"6ylC_iAs4JvDQzXeY6MuYQ",
   "iv":"ESpmcyGiZpRjc5urDela21TOOTW8Wqd1"
}
""".replacingWhiteSpacesAndNewLines()

let message_alice_skid_not_found = """
{
   "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTUiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ==",
   "recipients":[
      {
         "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
         "header":{
            "kid":"did:example:bob#key-x25519-1"
         }
      },
      {
         "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
         "header":{
            "kid":"did:example:bob#key-x25519-2"
         }
      },
      {
         "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
         "header":{
            "kid":"did:example:bob#key-x25519-3"
         }
      }
   ],
   "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
   "iv":"o02OXDQ6_-sKz2PX_6oyJg"
}
""".replacingWhiteSpacesAndNewLines()

let message_alice_and_bob_keys_different_curves = """
{
   "ciphertext":"MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_UVuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZCGaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9xDuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1vW4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
   "protected":"eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFfR2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRqTXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJhcHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGljYXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJFQ0RILTFQVStBMjU2S1cifQ==",
   "recipients":[
      {
         "encrypted_key":"o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjBDuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
         "header":{
            "kid":"did:example:bob#key-p384-1"
         }
      },
      {
         "encrypted_key":"rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7vjbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
         "header":{
            "kid":"did:example:bob#key-p384-2"
         }
      },
      {
         "encrypted_key":"aqfxMY2sV-njsVo-_9Ke9QbOf6hxhGrUVh_m-h_Aq530w3e_4IokChfKWG1tVJvXYv_AffY7vxj0k5aIfKZUxiNmBwC_QsNo",
         "header":{
            "kid":"did:example:bob#key-p384-3"
         }
      }
   ],
   "tag":"uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
   "iv":"o02OXDQ6_-sKz2PX_6oyJg"
}
""".replacingWhiteSpacesAndNewLines()

let message_protected_header_is_not_base64_encoded = """
{
   "payload":"eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3NhbCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVhdGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNzYWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
   "signatures":[
      {
         "protected":"eyJ\\\\0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
         "signature":"FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
         "header":{
            "kid":"did:example:alice#key-1"
         }
      }
   ]
}
""".replacingWhiteSpacesAndNewLines()
