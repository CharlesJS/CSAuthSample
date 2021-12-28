//
//  main.swift
//  CSAuthSample Example Helper Tool
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleHelper
import Darwin

func sayHello(message: String) async throws -> String {
    let replyMessage = """
        Received message from app: “\(message)”
        Sending reply to app: “Hello app! My UID is \(getuid()) and my GID is \(getgid())!”
        """

    return replyMessage
}

let helperTool = HelperTool()

helperTool.setHandler(command: ExampleCommands.sayHello, handler: sayHello)

helperTool.run()
