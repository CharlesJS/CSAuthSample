//
//  ExampleHelperTool.swift
//  Example Helper Tool
//
//  Created by Charles Srstka on 4/15/20.
//  Copyright © 2020-2021 Charles Srstka. All rights reserved.
//

import CSAuthSampleHelper
import Security.Authorization
import SwiftyXPC
import os

class ExampleHelperTool: HelperTool<ExampleCommands> {
    override func handleCommand(
        command: ExampleCommands,
        request: [String : Any]?,
        authorization: AuthorizationRef,
        connection: XPCConnection
    ) async throws -> [String : Any]? {
        switch command {
        case .sayHello:
            return try await self.sayHello(message: request?.debugDescription ?? "(no message")
        }
    }

    func sayHello(message: String) async throws -> [String : Any] {
        let replyMessage = """
            Received message from app: “\(message)”
            Sending reply to app: “Hello app! My UID is \(getuid()) and my GID is \(getgid())!”
            """

        return ["Message" : replyMessage]
    }
}
