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
    private let helperClient: HelperClient

    private init(helperClient: HelperClient) {
        self.helperClient = helperClient
    }

    static func main() {
        do {
            let helperClient = try HelperClient(
                helperID: "com.charlessoft.CSAuthSample-Example.helper",
                commandSet: ExampleCommands.all,
                bundle: .main,
                tableName: "Prompts"
            )

            let xpcService = XPCService(helperClient: helperClient)

            let requirement: String? = nil
            let serviceListener = try XPCListener(type: .service, codeSigningRequirement: requirement)

            serviceListener.setMessageHandler(name: ExampleCommands.sayHello.name, handler: xpcService.sayHello)
            serviceListener.setMessageHandler(name: BuiltInCommands.getVersion.name, handler: xpcService.getHelperVersion)
            serviceListener.setMessageHandler(name: BuiltInCommands.uninstallHelperTool.name, handler: xpcService.uninstall)

            serviceListener.errorHandler = xpcService.handleError

            serviceListener.activate()
            fatalError("Should not get here")
        } catch {
            fatalError("Error while setting up XPC service: \(error)")
        }
    }

    private func sayHello(_: XPCConnection, message: String) async throws -> String {
        do {
        return try await self.helperClient.executeInHelperTool(
            command: ExampleCommands.sayHello,
            request: message
        )
        } catch {
            let e = error
            NSLog("error: \(e)")
            throw e
        }
    }

    private func getHelperVersion(_: XPCConnection) async throws -> String {
        try await self.helperClient.requestHelperVersion()
    }

    private func uninstall(_: XPCConnection) async throws {
        try await self.helperClient.uninstallHelperTool()
    }

    private func handleError(connection: XPCConnection, error: Error) {
        if #available(macOS 11.0, *) {
            os.Logger().error("Received error: \(error.localizedDescription)")
        } else {
            os_log(.error, "Received error: %@", error.localizedDescription)
        }
    }
}
