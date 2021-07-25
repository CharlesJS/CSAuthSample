//
//  File.swift
//  File
//
//  Created by Charles Srstka on 7/24/21.
//

import XPC

public struct XPCEndpoint: XPCConvertible {
    private let endpoint: xpc_endpoint_t

    public init(connection: xpc_connection_t) {
        self.endpoint = xpc_endpoint_create(connection)
    }

    public func createConnection() -> xpc_connection_t {
        xpc_connection_create_from_endpoint(self.endpoint)
    }

    public static func fromXPCObject(_ xpcObject: xpc_object_t) -> XPCConvertible? {
        XPCEndpoint(connection: xpcObject)
    }

    public func toXPCObject() -> xpc_object_t? {
        self.endpoint
    }
}