//
//  File.swift
//  File
//
//  Created by Charles Srstka on 7/24/21.
//

import Foundation

enum ConnectionError: Error {
    case connectionInterrupted
    case connectionInvalid
    case unexpectedConnection
    case unexpectedEvent
}
