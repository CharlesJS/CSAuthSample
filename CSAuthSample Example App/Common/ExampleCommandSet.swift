//
//  ExampleCommandSet.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleCommon
import CoreFoundation
import Security.AuthorizationDB
import SwiftyXPC

struct ExampleCommands {
    static let all = [Self.sayHello]

    static let sayHello = CommandSpec(
        name: "com.charlessoft.CSAuthSample-Example.Commands.SayHello",
        rule: kAuthorizationRuleAuthenticateAsAdmin,
        prompt: CFBundleCopyLocalizedString(
            CFBundleGetMainBundle(),
            CFString.fromString("SayHello"),
            nil,
            CFString.fromString("Prompts")
        ).toString(),
        requestType: String.self,
        responseType: .wait(String.self)
    )

    static let openSudoLectureFile = CommandSpec(
        name: "com.charlessoft.CSAuthSample-Example.Commands.OpenSudoLectureFile",
        rule: kAuthorizationRuleAuthenticateAsAdmin,
        prompt: CFBundleCopyLocalizedString(
            CFBundleGetMainBundle(),
            CFString.fromString("OpenSudoLectureFile"),
            nil,
            CFString.fromString("Prompts")
        ).toString(),
        responseType: .wait(XPCFileDescriptor.self)
    )
}
