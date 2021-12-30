//
//  main.swift
//  CSAuthSample Example Helper Tool
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleHelper
import CSCoreFoundation
import CoreFoundation
import SwiftyXPC

func sayHello(message: String) async throws -> String {
    let replyMessage = """
        Received message from app: “\(message)”
        Sending reply to app: “Hello app! My UID is \(getuid()) and my GID is \(getgid())!”
        """

    return replyMessage
}

func openSudoLectureFile() async throws -> XPCFileDescriptor {
    let fd = open("/etc/sudo_lecture", O_RDONLY)
    guard fd >= 0 else {
        throw CFError.make(posixError: errno)
    }

    return XPCFileDescriptor(fileDescriptor: fd)
}

let helperTool = HelperTool()

helperTool.setHandler(command: ExampleCommands.sayHello, handler: sayHello)
helperTool.setHandler(command: ExampleCommands.openSudoLectureFile, handler: openSudoLectureFile)

helperTool.run()
