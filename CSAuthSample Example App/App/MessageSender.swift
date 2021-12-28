//
//  MessageSender.swift
//  Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleCommon
import SwiftyXPC
import Combine
import os
import Example_XPC_Service

actor MessageSender {
    static let shared = try! MessageSender()

    private var connection: XPCConnection
    @Published var messageSendInProgress = false

    private init() throws {
        let connection = try XPCConnection(type: .remoteService(bundleID: "com.charlessoft.CSAuthSample-Example.xpc"))

        if #available(macOS 11.0, *) {
            let logger = Logger()

            connection.errorHandler = { _, error in
                logger.error("The connection to the XPC service received an error: \(error.localizedDescription)")
            }
        } else {
            connection.errorHandler = { _, error in
                os_log(.error, "The connection to the XPC service received an error: %@", error.localizedDescription)
            }
        }

        connection.resume()

        self.connection = connection
    }

    func sayHello() async throws -> String {
        self.messageSendInProgress = true
        defer { self.messageSendInProgress = false }

        return try await self.connection.sendMessage(name: ExampleCommands.sayHello.name, request: "Hello, World!")
    }

    func getVersion() async throws -> String {
        self.messageSendInProgress = true
        defer { self.messageSendInProgress = false }

        return try await self.connection.sendMessage(name: BuiltInCommands.getVersion.name)
    }

    func uninstallHelperTool() async throws -> String {
        try await self.connection.sendMessage(name: BuiltInCommands.uninstallHelperTool.name)

        return "Uninstall Successful"
    }
}
