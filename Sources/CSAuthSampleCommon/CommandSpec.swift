//
//  CommandSpec.swift
//  Helper Library
//
//  Created by Charles Srstka on 7/14/2021.
//

import CSCoreFoundation
import CoreGraphics
import Darwin.POSIX.syslog
import Security.AuthorizationDB
import SwiftyXPC
import System

/// A structure representing a command that can be executed in the helper tool.
///
/// Create a `CommandSpec` for each command that your helper tool needs to accept, and pass an array containing all of your custom `CommandSpec`s to
/// `HelperClient`'s initializer in the app. In your helper tool, call `HelperTool`'s `setHandler` family of methods with each command to assign it to
/// a helper function that will implement the command.
public struct CommandSpec: Equatable {
    /// Determines whether or not the application should wait for a reply from the helper tool, and type of the value it returns, if any.
    public enum ResponseType {
        /// The application should wait for a response. If the parameter is non-`nil`, the tool will return a value from its helper function.
        case wait(Codable.Type?)
        /// The application should continue without waiting for a response from the helper tool. If the helper function returns a value, this is considered an error.
        case noWait
    }

    /// A string uniquely identifying this command.
    public let name: String

    /// A rule name determining what users are allowed to access this command, whether authentication is required, etc.
    ///
    /// A set of pre-fabricated rules to use for this parameter can be found in `Security.framework/Versions/A/Headers/AuthorizationDB.h`.
    public let rule: String

    /// An optional string that will be displayed during authorization prompts.
    public let prompt: String?

    /// The type of the parameter that this command’s helper function accepts.
    ///
    /// Nil if the helper function does not take any parameters.
    public let requestType: Codable.Type?

    /// Determines whether or not the application should wait for a reply from the helper tool, and type of the value it returns, if any.
    public let responseType: ResponseType

    /// Create a new `CommandSpec`.
    ///
    /// - Parameters:
    ///   - name: A string uniquely identifying this command.
    ///   - rule: A rule name determining what users are allowed to access this command, whether authentication is required, etc. A set of pre-fabricated rules to use for this parameter can be found in `Security.framework/Versions/A/Headers/AuthorizationDB.h`.
    ///   - prompt: A string that will be displayed during authorization prompts. Optional.
    ///   - requestType: The type of the parameter that this command’s helper function accepts. Nil if the helper function does not take any parameters.
    ///   - responseType: Determines whether or not the application should wait for a reply from the helper tool, and type of the value it returns, if any.
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

    /// Required for implementation of `Equatable` protocol.
    ///
    /// - Parameters:
    ///   - lhs: A `CommandSpec`.
    ///   - rhs: A `CommandSpec`.
    ///
    /// - Returns: A boolean value indicating whether or not the two commands are equal.
    public static func == (lhs: CommandSpec, rhs: CommandSpec) -> Bool {
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
    @available(macOS, deprecated: 13.0, message: "Simply call `unregisterHelperTool()` on the helper client instead")
    public static let uninstallHelperTool = CommandSpec(
        name: "com.charlessoft.CSAuthSample.ConnectWithEndpoint",
        rule: kAuthorizationRuleClassAllow
    )
}
