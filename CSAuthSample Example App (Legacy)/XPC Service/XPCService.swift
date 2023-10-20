//
//  XPCService.swift
//  Example App XPC Service
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleApp
import CSAuthSampleCommon
import Foundation
import SwiftyXPC
import System
import os

@main
class XPCService {
    private let helperClient: HelperClient

    private init(helperClient: HelperClient) {
        self.helperClient = helperClient
    }

    static func main() {
        do {
            let helperClient = try HelperClient(
                helperID: "com.charlessoft.CSAuthSample-LegacyExample.helper",
                commandSet: ExampleCommands.all,
                bundle: .main,
                tableName: "Prompts"
            )

            let xpcService = XPCService(helperClient: helperClient)

            let requirement: String? = nil
            let serviceListener = try XPCListener(type: .service, codeSigningRequirement: requirement)

            serviceListener.setMessageHandler(name: ExampleCommands.sayHello.name, handler: xpcService.sayHello)
            serviceListener.setMessageHandler(
                name: ExampleCommands.openSudoLectureFile.name,
                handler: xpcService.openSudoLectureFile
            )
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
        try await self.helperClient.executeInHelperTool(command: ExampleCommands.sayHello, request: message)
    }

    private func openSudoLectureFile(_: XPCConnection) async throws -> XPCFileDescriptor {
        try await self.helperClient.executeInHelperTool(command: ExampleCommands.openSudoLectureFile)
    }

    private func getHelperVersion(_: XPCConnection) async throws -> String {
        try await self.helperClient.requestHelperVersion()
    }

    private func uninstall(_: XPCConnection) async throws {
        try await self.helperClient.unregisterHelperTool()
    }

    private func handleError(connection: XPCConnection, error: Error) {
        if #available(macOS 11.0, *) {
            os.Logger().error("Received error: \(error.localizedDescription)")
        } else {
            os_log(.error, "Received error: %@", error.localizedDescription)
        }
    }
}
