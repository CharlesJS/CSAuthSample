//
//  ExampleCommandSet.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleCommon
import CoreFoundation
import Security.Authorization

enum ExampleCommands: String, Command, CaseIterable {
    case sayHello = "com.charlessoft.CSAuthSample-Example.Commands.SayHello"

    var rule: String {
        switch self {
        case .sayHello:
            return kAuthorizationRuleAuthenticateAsAdmin
        }
    }

    var prompt: String? {
        switch self {
        case .sayHello:
            let bundle = CFBundleGetMainBundle()
            return CFBundleCopyLocalizedString(
                bundle,
                CFString.fromString("SayHello"),
                nil,
                CFString.fromString("Prompts")
            ).toString()
        }
    }
}
