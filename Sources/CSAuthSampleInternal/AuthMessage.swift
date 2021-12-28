//
//  AuthMessage.swift
//  
//
//  Created by Charles Srstka on 12/25/21.
//

import Security.AuthorizationDB
import CSCoreFoundation

public struct AuthMessage<Body: Codable>: Codable {
    private enum Key: CodingKey {
        case authorization
        case expectedVersion
        case body
    }

    public let authorization: AuthorizationRef?
    public let expectedVersion: String?
    public let body: Body

    public init(authorization: AuthorizationRef?, expectedVersion: String?, body: Body) {
        self.authorization = authorization
        self.expectedVersion = expectedVersion
        self.body = body
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Key.self)

        if let authBytes = try container.decodeIfPresent([UInt8].self, forKey: .authorization) {
            let authSize = MemoryLayout<AuthorizationExternalForm>.stride
            guard authBytes.count >= authSize else {
                let description = "Authorization bytes too short; need \(authSize), have \(authBytes.count)"
                throw DecodingError.dataCorruptedError(forKey: .authorization, in: container, debugDescription: description)
            }

            self.authorization = try authBytes.withUnsafeBytes {
                let pointer = $0.bindMemory(to: AuthorizationExternalForm.self).baseAddress!
                var authorization: AuthorizationRef? = nil

                let err = AuthorizationCreateFromExternalForm(pointer, &authorization)
                guard err == errAuthorizationSuccess, let authorization = authorization else {
                    throw CFError.make(osStatus: err)
                }

                return authorization
            }
        } else {
            self.authorization = nil
        }

        self.expectedVersion = try container.decodeIfPresent(String.self, forKey: .expectedVersion)
        self.body = try container.decode(Body.self, forKey: .body)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: Key.self)

        if let authorization = self.authorization {
            var authBytes = [UInt8](repeating: 0, count: MemoryLayout<AuthorizationExternalForm>.stride)

            try authBytes.withUnsafeMutableBytes {
                let ptr = $0.bindMemory(to: AuthorizationExternalForm.self).baseAddress!
                let err = AuthorizationMakeExternalForm(authorization, ptr)
                guard err == errAuthorizationSuccess else { throw CFError.make(osStatus: err) }
            }

            try container.encode(authBytes, forKey: .authorization)
        }

        try container.encode(self.expectedVersion, forKey: .expectedVersion)
        try container.encode(self.body, forKey: .body)
    }
}
