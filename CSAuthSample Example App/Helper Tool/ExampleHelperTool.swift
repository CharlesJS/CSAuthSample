//
//  ExampleHelperTool.swift
//  Example Helper Tool
//
//  Created by Charles Srstka on 4/15/20.
//  Copyright © 2020-2021 Charles Srstka. All rights reserved.
//

import CSAuthSampleHelper
import CoreFoundation
import Security.Authorization
import XPC

class ExampleHelperTool: HelperTool<ExampleCommands> {
    override func handleCommand(
        command: ExampleCommands,
        request: CFDictionary?,
        authorization: AuthorizationRef,
        connection: xpc_connection_t
    ) async throws -> CFDictionary? {
        switch command {
        case .sayHello:
            return try await self.sayHello(message: unsafeBitCast(request?["Message"], to: CFString?.self)?.toString() ?? "(no message)")
        }
    }

    func sayHello(message: String) async throws -> CFDictionary {
        let message = """
            Received message from app: “\(message)”
            Sending reply to app: “Hello app! My UID is \(getuid()) and my GID is \(getgid())!
            """

        var keyCallBacks = kCFTypeDictionaryKeyCallBacks
        var valueCallbacks = kCFTypeDictionaryValueCallBacks
        let response = CFDictionaryCreateMutable(kCFAllocatorDefault, 1, &keyCallBacks, &valueCallbacks)!

        let key = CFString.fromString("Message")
        let value = CFString.fromString(message)

        CFDictionarySetValue(
            response,
            unsafeBitCast(key, to: UnsafeMutableRawPointer.self),
            unsafeBitCast(value, to: UnsafeMutableRawPointer.self)
        )

        return response
    }
}
