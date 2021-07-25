//
//  File.swift
//  File
//
//  Created by Charles Srstka on 7/24/21.
//

import Foundation
import XPC

public enum ConnectionError: LocalizedError {
    case connectionInterrupted
    case connectionInvalid
    case unexpectedConnection
    case unexpectedEvent

    public var failureReason: String? {
        switch self {
        case .connectionInterrupted:
            let rawError = xpc_copy_description(XPC_ERROR_CONNECTION_INTERRUPTED)
            defer { free(UnsafeMutableRawPointer(mutating: rawError)) }
            return String(cString: rawError)
        case .connectionInvalid:
            let rawError = xpc_copy_description(XPC_ERROR_CONNECTION_INVALID)
            defer { free(UnsafeMutableRawPointer(mutating: rawError)) }
            return String(cString: rawError)
        case .unexpectedConnection:
            return String(localized: "Unexpected XPC connection")
        case .unexpectedEvent:
            return String(localized: "Unexpected XPC event")
        }
    }
}
