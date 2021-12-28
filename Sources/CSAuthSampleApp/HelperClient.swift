//
//  HelperClient.swift
//  App Library
//
//  Created by Charles Srstka on 6/25/18.
//

import CSAuthSampleCommon
import CSAuthSampleInternal
import Foundation
import ServiceManagement
import System
import SwiftyXPC

/// The primary class used by your application to communicate with your helper tool.
///
/// To use, create an instance and use `connectToHelperTool` to send messages to the helper tool.
public class HelperClient {
    let helperID: String
    let version: String

    private var _authorization: AuthorizationRef?
    private var authorization: AuthorizationRef {
        get throws {
            if let authorization = self._authorization {
                return authorization
            }

            var authorization: AuthorizationRef?
            let err = AuthorizationCreate(nil, nil, [], &authorization)
            if err != errAuthorizationSuccess { throw CFError.make(osStatus: err) }

            self._authorization = authorization

            return try authorization ?? { throw CocoaError(.fileReadUnknown) }()
        }
    }

    private static let _globalInit: Void = { csAuthSampleGlobalInit() }()

    /// Create a `HelperClient` object.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - version: The expected value of `CFBundleVersion` in the helper's Info.plist. Defaults to the main application's `CFBundleVersion`.
    ///   - authData: Authorization data, in the format of an `AuthorizationExternalForm`. If not provided, a new `AuthorizationRef` will be created.
    ///   - commandSet: A `CommandSet` object describing the messages the helper accepts, and their required authorization levels.
    ///   - bundle: A bundle containing a strings table containing localized messages to present to the user. Optional.
    ///   - tableName: The name of a strings table containing localized messages to present to the user. Optional.
    /// - Throws: Any errors that occur in the process of creating the `HelperClient`'s internal `AuthorizationRef`.
    public init(
        helperID: String,
        version: String = Bundle.main.infoDictionary?[kCFBundleVersionKey as String] as? String ?? "0",
        authorization: AuthorizationRef? = nil,
        commandSet: [CommandSpec],
        bundle: Bundle? = nil,
        tableName: String? = nil
    ) throws {
        _ = Self._globalInit

        self.helperID = helperID
        self.version = version

        let cfBundle = bundle == .main ? CFBundleGetMainBundle() : bundle.flatMap {
            CFBundleCreate(kCFAllocatorDefault, $0.bundleURL as CFURL)
        }

        try CommandSpec.setUpAccessRights(
            commandSet: commandSet,
            authorization: self.authorization,
            bundle: cfBundle,
            tableName: tableName
        )
    }

    deinit {
        _ = try? self.revokePrivileges()
    }

    /// Get the version of the helper tool.
    ///
    /// This is helpful for making sure that the application and helper tool are in sync with each other.
    /// If the helper's version does not match the app's version, it is generally a sign that the helper needs to be upgraded.
    public func requestHelperVersion() async throws -> String {
        try await self._executeInHelperTool(
            command: BuiltInCommands.getVersion,
            expectedVersion: nil,
            request: XPCNull.shared
        )
    }

    /// Install the helper tool.
    public func installHelperTool() async throws {
        _ = try? await self._uninstallHelperTool()

        try self.requestPrivileges([kSMRightBlessPrivilegedHelper], allowUserInteraction: true)
        try self.blessHelperTool()
    }

    /// Uninstall the helper tool.
    public func uninstallHelperTool() async throws {
        try self.requestPrivileges([kSMRightModifySystemDaemons], allowUserInteraction: true)

        try await self._uninstallHelperTool()

        try self.unblessHelperTool()
        try self.revokePrivileges()
    }

    private func _uninstallHelperTool() async throws {
        _ = try await self._executeInHelperTool(
            command: BuiltInCommands.uninstallHelperTool,
            expectedVersion: nil,
            request: XPCNull.shared
        ) as XPCNull
    }


    public func executeInHelperTool(command: CommandSpec, reinstallIfInvalid: Bool = true) async throws {
        try await self.executeInHelperTool(
            command: command,
            request: XPCNull.shared,
            reinstallIfInvalid: reinstallIfInvalid
        )
    }

    public func executeInHelperTool<Request: Codable>(
        command: CommandSpec,
        request: Request,
        reinstallIfInvalid: Bool = true
    ) async throws {
        _ = try await self.executeInHelperTool(
            command: command,
            request: request,
            reinstallIfInvalid: reinstallIfInvalid
        ) as XPCNull
    }

    public func executeInHelperTool<Response: Codable>(
        command: CommandSpec,
        reinstallIfInvalid: Bool = true
    ) async throws -> Response {
        try await self.executeInHelperTool(
            command: command,
            request: XPCNull.shared,
            reinstallIfInvalid: reinstallIfInvalid
        )
    }

    public func executeInHelperTool<Request: Codable, Response: Codable>(
        command: CommandSpec,
        request: Request,
        reinstallIfInvalid: Bool = true
    ) async throws -> Response {
        try validateArguments(command: command, requestType: type(of: request), responseType: Response.self)

        if command == BuiltInCommands.uninstallHelperTool {
            try await self.uninstallHelperTool()
            return XPCNull.shared as! Response
        }

        do {
            return try await self._executeInHelperTool(command: command, expectedVersion: self.version, request: request)
        } catch where reinstallIfInvalid {
            let reinstall: Bool

            if let error = error as? XPCError, case .connectionInvalid = error {
                reinstall = true
            } else if let error = error as? CSAuthSampleError, case .versionMismatch = error {
                reinstall = true
            } else {
                reinstall = false
            }

            if reinstall {
                try await self.installHelperTool()
                return try await self._executeInHelperTool(command: command, expectedVersion: self.version, request: request)
            } else {
                throw error
            }
        }
    }

    private func _executeInHelperTool<Request: Codable, Response: Codable>(
        command: CommandSpec,
        expectedVersion: String?,
        request: Request?
    ) async throws -> Response {
        try self.preauthorize(command: command)

        let connection = try XPCConnection(
            type: .remoteMachService(serviceName: self.helperID, isPrivilegedHelperTool: true)
        )

        let message = try AuthMessage(authorization: self.authorization, expectedVersion: expectedVersion, body: request)

        connection.activate()

        let replyMessage: AuthMessage<Response> = try await connection.sendMessage(name: command.name, request: message)

        return replyMessage.body
    }

    private func preauthorize(command: CommandSpec) throws {
        // Look up the command and preauthorize.  This has the nice side effect that
        // the authentication dialog comes up, in the typical case, here, rather than
        // in the helper tool.

        try command.name.withCString {
            var item = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)

            try withUnsafeMutablePointer(to: &item) {
                var rights = AuthorizationRights(count: 1, items: $0)

                let err = AuthorizationCopyRights(
                    try self.authorization,
                    &rights,
                    nil,
                    [.extendRights, .interactionAllowed, .preAuthorize],
                    nil
                )

                guard err == errAuthorizationSuccess else { throw CFError.make(osStatus: err) }
            }
        }
    }

    private func requestPrivileges(_ privileges: [String], allowUserInteraction: Bool = true) throws {
        if privileges.isEmpty { return }

        let items = UnsafeMutablePointer<AuthorizationItem>.allocate(capacity: privileges.count)

        for (index, eachPrivilege) in privileges.enumerated() {
            let name = eachPrivilege.withCString { strdup($0)! }
            items[index] = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        }

        defer {
            for index in 0..<privileges.count {
                free(UnsafeMutableRawPointer(mutating: items[index].name))
            }

            items.deallocate()
        }

        var rights = AuthorizationRights(count: UInt32(privileges.count), items: items)

        var flags: AuthorizationFlags = [.preAuthorize, .extendRights]
        if allowUserInteraction {
            flags.insert(.interactionAllowed)
        }

        // Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper).
        let err = AuthorizationCopyRights(try self.authorization, &rights, nil, flags, nil)
        guard err == errAuthorizationSuccess else { throw CFError.make(osStatus: err) }
    }

    private func revokePrivileges() throws {
        guard let auth = self._authorization else { return }

        let err = AuthorizationFree(auth, .destroyRights)
        guard err == errAuthorizationSuccess else { throw CFError.make(osStatus: err) }

        self._authorization = nil
    }

    private func blessHelperTool() throws {
        var smError: Unmanaged<CFError>?
        if !SMJobBless(kSMDomainSystemLaunchd, self.helperID as CFString, try self.authorization, &smError) {
            throw smError?.takeRetainedValue() ?? CocoaError(.fileWriteUnknown)
        }
    }
    
    private func unblessHelperTool() throws {
        var smError: Unmanaged<CFError>? = nil
        // deprecated, but there is still not a decent replacement, so 🤷
        // For now, kludge around the deprecation warning using dlsym.

        let remove = unsafeBitCast(
            dlsym(UnsafeMutableRawPointer(bitPattern: -1), "SMJobRemove"),
            to: (@convention(c) (CFString?, CFString, AuthorizationRef?, Bool, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool).self
        )

        if !remove(kSMDomainSystemLaunchd, self.helperID as CFString, try self.authorization, true, &smError) {
            throw smError?.takeRetainedValue() ?? CocoaError(.fileWriteUnknown)
        }
    }
}
