//
//  CommandSet.swift
//  Helper Library
//
//  Created by Charles Srstka on 7/14/2021.
//

import Security.AuthorizationDB
import Darwin.POSIX.syslog
import XPC
import CoreGraphics

public protocol Command {
    var name: String { get }
    var rule: String { get }
    var prompt: String? { get }
    var codeSigningRequirement: String? { get }

    static var allCommands: [Command] { get }

    static func setUpAccessRights(authorization: AuthorizationRef, bundle: CFBundle?, tableName: String?) throws
}

extension Command where Self : RawRepresentable, Self.RawValue == String {
    public var name: String { self.rawValue }
}

extension Command where Self : CaseIterable {
    public static var allCommands: [Command] { Array(self.allCases) }
}

/// Some built-in commands handled by the library which are provided for free.
public enum BuiltInCommands: String, CaseIterable, Command {
    /// Returns the version number of the tool.
    case getVersion = "com.charlessoft.CSAuthSample.UninstallHelperTool"

    /// Uninstalls the helper tool.
    case uninstallHelperTool = "com.charlessoft.CSAuthSample.ConnectWithEndpoint"

    // All of the built-in commands are operations that don't require authorization
    public var rule: String { kAuthorizationRuleClassAllow }
}

extension Command {
    public var prompt: String? { nil }
    public var codeSigningRequirement: String? { nil }

    private static var fullCommandSet: [Command] { BuiltInCommands.allCommands + Self.allCommands }

    public static subscript(commandName: String) -> Command? {
        Self.fullCommandSet.first { $0.name == commandName }
    }

    public static func setUpAccessRights(
        authorization: AuthorizationRef,
        bundle: CFBundle?,
        tableName: String?
    ) throws {
        for eachCommand in self.fullCommandSet {
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
                    throw convertOSStatusError(err)
                }
            } else {
                // A right already exists (err == noErr) or any other error occurs, we
                // assume that it has been set up in advance by the system administrator or
                // this is the second time we've run.  Either way, there's nothing more for
                // us to do.
            }
        }
    }
}
