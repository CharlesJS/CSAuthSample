//
//  ExampleCommandSet.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleCommon
import Foundation

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
            return Bundle.main.localizedString(forKey: "SayHello", value: nil, table: "Prompts")
        }
    }
}
