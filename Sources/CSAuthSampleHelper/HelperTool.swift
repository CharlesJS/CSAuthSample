//
//  HelperTool.swift
//  CSAuthSampleHelper
//
//  Created by Charles Srstka on 7/15/2021.
//
//

import System
import Security.Authorization
import CSAuthSampleCommon
import CoreFoundation
import SwiftyXPC
import os

open class HelperTool<CommandType: Command> {
    public let helperID: String
    public let codeSigningRequirement: String
    public let url: CFURL
    public let infoPlist: CFDictionary
    public let timeoutInterval: CFTimeInterval?

    private let logger: Logger

    public init(
        commandType _: CommandType.Type,
        helperID: String? = nil,
        codeSigningRequirement requirement: String? = nil,
        timeoutInterval: CFTimeInterval? = nil
    ) {
        let path = CFString.fromString(CommandLine.arguments.first!)

        self.url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, .cfurlposixPathStyle, false)
        self.infoPlist = CFBundleCopyInfoDictionaryForURL(self.url)

        self.helperID = helperID ?? self.infoPlist.readString(key: kCFBundleIdentifierKey) ?? {
            fatalError("Helper ID must be specified, either in code or via \(kCFBundleIdentifierKey!) in Info.plist")
        }()

        if let requirement = requirement {
            self.codeSigningRequirement = requirement
        } else if let authorizedClients: CFArray = self.infoPlist["SMAuthorizedClients", as: CFArrayGetTypeID()],
                  CFArrayGetCount(authorizedClients) > 0,
                  let requirement = (authorizedClients[0, as: CFStringGetTypeID()] as CFString?)?.toString() {
            self.codeSigningRequirement = requirement
        } else {
            fatalError("A code signing requirement must be specified")
        }

        self.timeoutInterval = timeoutInterval

        self.logger = Logger(subsystem: self.helperID, category: "com.charlessoft.CSAuthSample.HelperTool")
    }

    open func handleCommand(
        command: CommandType,
        request: [String : Any]?,
        authorization: AuthorizationRef,
        connection: XPCConnection
    ) async throws -> [String : Any]? {
        fatalError("Must override handleCommand(command:request:authorization:connection:)!")
    }

    public func run() -> Never {
        let listener = try! XPCListener(
            type: .machService(name: self.helperID),
            codeSigningRequirement: self.codeSigningRequirement
        )

        listener.messageHandler = self.handleMessage
        listener.errorHandler = self.handleError

        listener.activate()
        dispatchMain()
    }

    private func handleError(connection: XPCConnection, error: Error) {
        switch error {
        case XPCError.connectionInvalid:
            self.logger.notice("The XPC connection went invalid")
        case XPCError.terminationImminent:
            self.logger.notice("Termination imminent")
        default:
            self.logger.notice("Something went wrong: \(error._domain) error \(error._code)")
        }
    }

    private func handleMessage(connection: XPCConnection, message: [String : Any]) async throws -> [String : Any]? {
        guard let commandName = message[DictionaryKeys.commandName] as? String,
              let command = CommandType[commandName] else {
            throw Errno.invalidArgument
        }

        guard let authFormData = message[DictionaryKeys.authData, as: CFDataGetTypeID()] as CFData?,
              CFDataGetLength(authFormData) >= MemoryLayout<AuthorizationExternalForm>.size else {
                  throw Errno.invalidArgument
        }

        var authorization: AuthorizationRef? = nil
        let err = CFDataGetBytePtr(authFormData).withMemoryRebound(to: AuthorizationExternalForm.self, capacity: 1) {
            AuthorizationCreateFromExternalForm($0, &authorization)
        }

        guard err == errAuthorizationSuccess, let authorization = authorization else { throw CFError.make(err) }

        try self.checkAuthorization(command: command, authorization: authorization)

        if let command = command as? BuiltInCommands {
            return try self.handleBuiltInCommand(command)
        } else if let command = command as? CommandType {
            return try await handleCommand(
                command: command,
                request: message[DictionaryKeys.request] as? [String : Any],
                authorization: authorization,
                connection: connection
            )
        } else {
            throw Errno.invalidArgument
        }
    }

    private func checkAuthorization(command: Command, authorization auth: AuthorizationRef) throws {
        // Acquire the associated right for the command.
        try command.name.withCString {
            var item = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)

            try withUnsafeMutablePointer(to: &item) {
                var rights = AuthorizationRights(count: 1, items: $0)

                let err = AuthorizationCopyRights(auth, &rights, nil, [.extendRights, .interactionAllowed], nil)

                if err != errAuthorizationSuccess { throw CFError.make(err) }
            }
        }
    }
}
