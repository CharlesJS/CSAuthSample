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
import CSAuthSampleInternal
import CSCoreFoundation
import CoreFoundation
import SwiftyXPC
import os

public class HelperTool {
    public let helperID: String
    public let codeSigningRequirement: String
    public let url: CFURL
    public let infoPlist: CFDictionary

    public private(set) lazy var version: String? = {
        let key = unsafeBitCast(kCFBundleVersionKey, to: UnsafeRawPointer.self)
        let value = CFDictionaryGetValue(self.infoPlist, key)

        return unsafeBitCast(value, to: CFString?.self)?.toString()
    }()

    private enum LoggerPolyfill {
        case logger(Any)
        case legacy

        init(helperID: String, category: String) {
            if #available(macOS 11.0, *) {
                self = .logger(Logger(subsystem: helperID, category: category))
            } else {
                self = .legacy
            }
        }

        func notice(_ string: String) {
            if #available(macOS 11.0, *), case .logger(let logger) = self {
                (logger as! Logger).notice("\(string)")
            } else {
                NSLog(string)
            }
        }
    }

    private let listener: XPCListener
    private let logger: LoggerPolyfill

    private static let _globalInit: Void = { csAuthSampleGlobalInit() }()

    public init(
        helperID: String? = nil,
        codeSigningRequirement requirement: String? = nil
    ) {
        _ = Self._globalInit

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

        self.listener = try! XPCListener(
            type: .machService(name: self.helperID),
            codeSigningRequirement: self.codeSigningRequirement
        )

        self.logger = LoggerPolyfill(helperID: self.helperID, category: "com.charlessoft.CSAuthSample.HelperTool")
    }

    public func setHandler(command: CommandSpec, handler: @escaping () async throws -> ()) {
        self.setHandler(command: command) { () async throws -> XPCNull in
            try await handler()
            return XPCNull.shared
        }
    }

    public func setHandler<Response: Codable>(command: CommandSpec, handler: @escaping () async throws -> Response) {
        self.setHandler(command: command) { (_: XPCNull) in try await handler() }
    }

    public func setHandler<Request: Codable>(command: CommandSpec, handler: @escaping (Request) async throws -> ()) {
        self.setHandler(command: command) { (request: Request) async throws -> XPCNull in
            try await handler(request)
            return XPCNull.shared
        }
    }

    public func setHandler<Request: Codable, Response: Codable>(
        command: CommandSpec,
        handler: @escaping (Request) async throws -> Response
    ) {
        do {
            try validateArguments(command: command, requestType: Request.self, responseType: Response.self)
        } catch {
            preconditionFailure("Incorrect request and/or response type")
        }

        let xpcHandler: (XPCConnection, AuthMessage<Request>) async throws -> AuthMessage<Response> = { _, message in
            if let expectedVersion = message.expectedVersion, expectedVersion != self.version {
                throw CSAuthSampleError.versionMismatch(expected: expectedVersion, actual: self.version ?? "(nil)")
            }

            guard let authorization = message.authorization else {
                throw CFError.make(posixError: EINVAL)
            }

            try self.checkAuthorization(command: command, authorization: authorization)

            let response = try await handler(message.body)

            return AuthMessage(authorization: nil, expectedVersion: nil, body: response)
        }

        self.listener.setMessageHandler(name: command.name, handler: xpcHandler)
    }

    public func run() -> Never {
        self.setUpBuiltInHandlers()

        self.listener.errorHandler = self.handleError
        self.listener.activate()

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

    private func checkAuthorization(command: CommandSpec, authorization auth: AuthorizationRef) throws {
        // Acquire the associated right for the command.
        try command.name.withCString {
            var item = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)

            try withUnsafeMutablePointer(to: &item) {
                var rights = AuthorizationRights(count: 1, items: $0)

                let err = AuthorizationCopyRights(auth, &rights, nil, [.extendRights, .interactionAllowed], nil)

                if err != errAuthorizationSuccess { throw CFError.make(osStatus: err) }
            }
        }
    }
}
