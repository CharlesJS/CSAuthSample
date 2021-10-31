//
//  XPCService.swift
//  Example App XPC Service
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleApp
import CSAuthSampleCommon
import SwiftyXPC
import System
import os
import Foundation

@main
class XPCService {
    private let logger = os.Logger()

    private let helperClient = try! HelperClient(
        helperID: "com.charlessoft.CSAuthSample-Example.helper",
        commandType: ExampleCommands.self,
        bundle: .main,
        tableName: "Prompts"
    )

    static func main() {
        do {
            let xpcService = XPCService()

            let requirement: String? = nil
            let serviceListener = try XPCListener(type: .service, codeSigningRequirement: requirement)

            serviceListener.messageHandler = xpcService.handleMessage
            serviceListener.errorHandler = xpcService.handleError

            serviceListener.activate()
            fatalError("Should not get here")
        } catch {
            fatalError("Error while setting up XPC service: \(error)")
        }
    }

    private func handleMessage(connection: XPCConnection, message: [String : Any]) async throws -> [String : Any]? {
        // Sanity check to make sure the message is a valid helper command
        let allowedCommands: [Command] = [
            ExampleCommands.sayHello,
            BuiltInCommands.getVersion,
            BuiltInCommands.uninstallHelperTool
        ]

        guard let commandName = message[CSAuthSampleCommon.DictionaryKeys.commandName] as? String,
              let command: Command = ExampleCommands(rawValue: commandName) ?? BuiltInCommands(rawValue: commandName),
              allowedCommands.contains(where: { $0.name == commandName }),
              let request = message[CSAuthSampleCommon.DictionaryKeys.request] as? [String : Any] else {
            throw Errno.invalidArgument
        }

        return try await self.helperClient.executeInHelperTool(
            command: command,
            request: request,
            reinstallIfInvalid: true
        )
    }

    private func handleError(connection: XPCConnection, error: Error) {
        self.logger.error("Received error: \(error.localizedDescription)")
    }
}
