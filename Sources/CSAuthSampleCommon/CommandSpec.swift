//
//  CommandSpec.swift
//  Helper Library
//
//  Created by Charles Srstka on 7/14/2021.
//

import CSCoreFoundation
import Security.AuthorizationDB
import Darwin.POSIX.syslog
import CoreGraphics
import System
import SwiftyXPC

public struct CommandSpec: Equatable {
    public enum ResponseType {
        case wait(Codable.Type?)
        case noWait
    }

    public let name: String
    public let rule: String
    public let prompt: String?

    public let requestType: Codable.Type?
    public let responseType: ResponseType

    public init(
        name: String,
        rule: String,
        prompt: String? = nil,
        requestType: Codable.Type? = nil,
        responseType: ResponseType = .wait(nil)
    ) {
        self.name = name
        self.rule = rule
        self.prompt = prompt
        self.requestType = requestType
        self.responseType = responseType
    }

    public static func setUpAccessRights(
        commandSet: [CommandSpec],
        authorization: AuthorizationRef,
        bundle: CFBundle?,
        tableName: String?
    ) throws {
        for eachCommand in BuiltInCommands.all + commandSet {
            // First get the right.  If we get back errAuthorizationDenied that means there's
            // no current definition, so we add our default one.

            var err = AuthorizationRightGet(eachCommand.name, nil)

            if err == errAuthorizationDenied {
                err = AuthorizationRightSet(
                    authorization,
                    eachCommand.name,
                    CFString.fromString(eachCommand.rule),
                    eachCommand.prompt.map { CFString.fromString($0) },
                    bundle,
                    tableName.map { CFString.fromString($0) }
                )

                guard err == errAuthorizationSuccess else {
                    throw CFError.make(osStatus: err)
                }
            } else {
                // A right already exists (err == noErr) or any other error occurs, we
                // assume that it has been set up in advance by the system administrator or
                // this is the second time we've run.  Either way, there's nothing more for
                // us to do.
            }
        }
    }

    public static func ==(lhs: CommandSpec, rhs: CommandSpec) -> Bool {
        if lhs.name != rhs.name || lhs.rule != rhs.rule || lhs.prompt != rhs.prompt || lhs.requestType != rhs.requestType {
            return false
        }

        switch lhs.responseType {
        case .noWait:
            switch rhs.responseType {
            case .noWait:
                return true
            case .wait:
                return false
            }
        case .wait(let lhsType):
            switch rhs.responseType {
            case .noWait:
                return false
            case .wait(let rhsType):
                return lhsType == rhsType
            }
        }
    }
}

/// Some built-in commands handled by the library which are provided for free.
public struct BuiltInCommands {
    /// Returns the version number of the tool.
    public static let getVersion = CommandSpec(
        name: "com.charlessoft.CSAuthSample.UninstallHelperTool",
        rule: kAuthorizationRuleClassAllow,
        responseType: .wait(String.self)
    )
        
    /// Uninstalls the helper tool.
    public static let uninstallHelperTool = CommandSpec(
        name: "com.charlessoft.CSAuthSample.ConnectWithEndpoint",
        rule: kAuthorizationRuleClassAllow
    )

    fileprivate static let all: [CommandSpec] = [Self.getVersion, Self.uninstallHelperTool]
}
