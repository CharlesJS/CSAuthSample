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

    private let logger: Logger

    private init() throws {
        let connection = try XPCConnection(type: .remoteService(bundleID: "com.charlessoft.CSAuthSample-Example.xpc"))
        let logger = Logger()

        connection.errorHandler = { _, error in
            logger.error("The connection to the XPC service received an error: \(error.localizedDescription)")
        }

        connection.resume()

        self.connection = connection
        self.logger = logger
    }

    func sayHello() async throws -> String {
        let reply = try await self.sendMessage(command: ExampleCommands.sayHello, request: ["Hello" : "World"])

        return reply["Message"] as? String ?? "(no message)"
    }

    func uninstallHelperTool() async throws -> String {
         _ = try await self.sendMessage(command: BuiltInCommands.uninstallHelperTool, request: [:])

        return "Uninstall Successful"
    }

    private func sendMessage(command: Command, request: [String : Any]) async throws -> [String : Any] {
        self.messageSendInProgress = true
        defer { self.messageSendInProgress = false }

        let message: [String : Any] = [
            CSAuthSampleCommon.DictionaryKeys.commandName: command.name,
            CSAuthSampleCommon.DictionaryKeys.request: request
        ]

        return try await self.connection.sendMessage(message)
    }
}
