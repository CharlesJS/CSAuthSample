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
import SwiftyXPC
import System

/// The primary class used by your application to communicate with your helper tool.
///
/// To use, create an instance and use the `executeInHelperTool(command:request:reinstallIfInvalid:)` method to send messages to the helper tool.
public class HelperClient {
    /// The bundle identifier of your helper tool.
    public let helperID: String
    private let plistName: String?

    /// The version of your helper tool.
    public let version: String

    private var _authorization: AuthorizationRef?
    // https://bugs.swift.org/browse/SR-15671
    // swift-format-ignore: UseSingleLinePropertyGetter
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

    /// Create a `HelperClient` object for use in applications targeting macOS 13.0 or higher.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - plistName: The path to the launchd plist for your helper tool. This plist should reside in `Contents/Library/LaunchDaemons`
    ///     within your application or XPC service’s bundle.
    ///   - version: The expected value of `CFBundleVersion` in the helper's Info.plist. Defaults to the main application's `CFBundleVersion`.
    ///   - authorization: An `AuthorizationRef` representing the current authorization session. If `nil`, a new one will be created automatically.
    ///   - commandSet: An array of `CommandSpec` objects describing the messages the helper accepts, and their required authorization levels. 
    ///     Does not need to include the contents of `BuiltInCommands`, as those will be automatically added to the array.
    ///   - bundle: A bundle containing a strings table containing localized messages to present to the user. Optional.
    ///   - tableName: The name of a strings table containing localized messages to present to the user. Optional.
    /// - Throws: Any errors that occur in the process of creating the `HelperClient`'s internal `AuthorizationRef`.
    @available(macOS 13.0, *)
    public convenience init(
        helperID: String,
        plistName: String,
        version: String = Bundle.main.infoDictionary?[kCFBundleVersionKey as String] as? String ?? "0",
        authorization: AuthorizationRef? = nil,
        commandSet: [CommandSpec],
        bundle: Bundle? = nil,
        tableName: String? = nil
    ) throws {
        try self.init(
            helperID: helperID,
            maybePlistName: plistName,
            version: version,
            authorization: authorization,
            commandSet: commandSet,
            bundle: bundle,
            tableName: tableName
        )
    }
    
    /// Create a `HelperClient` object using the legacy service management APIs, for use in applications targeting macOS versions earlier than 13.0.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - version: The expected value of `CFBundleVersion` in the helper's Info.plist. Defaults to the main application's `CFBundleVersion`.
    ///   - authorization: An `AuthorizationRef` representing the current authorization session. If `nil`, a new one will be created automatically.
    ///   - commandSet: An array of `CommandSpec` objects describing the messages the helper accepts, and their required authorization levels. Does not need to include the contents of `BuiltInCommands`, as those will be automatically added to the array.
    ///   - bundle: A bundle containing a strings table containing localized messages to present to the user. Optional.
    ///   - tableName: The name of a strings table containing localized messages to present to the user. Optional.
    /// - Throws: Any errors that occur in the process of creating the `HelperClient`'s internal `AuthorizationRef`.
    @available(macOS, deprecated: 13.0, message: "Use init(helperID:plistName:...) instead")
    public convenience init(
        helperID: String,
        version: String = Bundle.main.infoDictionary?[kCFBundleVersionKey as String] as? String ?? "0",
        authorization: AuthorizationRef? = nil,
        commandSet: [CommandSpec],
        bundle: Bundle? = nil,
        tableName: String? = nil
    ) throws {
        try self.init(
            helperID: helperID,
            maybePlistName: nil,
            version: version,
            authorization: authorization,
            commandSet: commandSet,
            bundle: bundle,
            tableName: tableName
        )
    }

    private init(
        helperID: String,
        maybePlistName: String?,
        version: String,
        authorization: AuthorizationRef?,
        commandSet: [CommandSpec],
        bundle: Bundle?,
        tableName: String?
    ) throws {
        _ = Self._globalInit

        self.helperID = helperID
        self.plistName = maybePlistName
        self.version = version

        let cfBundle: CFBundle?
        if bundle == .main {
            cfBundle = CFBundleGetMainBundle()
        } else {
            cfBundle = bundle.flatMap {
                CFBundleCreate(kCFAllocatorDefault, $0.bundleURL as CFURL)
            }
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
    ///
    /// - Returns: The version of the currently-installed helper tool.
    ///
    /// - Throws: Any error that occurs in the process of communicating with the helper tool.
    public func requestHelperVersion() async throws -> String {
        try await self._executeInHelperTool(
            command: BuiltInCommands.getVersion,
            expectedVersion: nil,
            request: XPCNull.shared
        )
    }

    /// Register the helper tool.
    /// When using the legacy API, this will also install the helper tool in `/Library/PrivilegedHelperTools`.
    ///
    /// - Throws: Any error that occurs during the process of installing or registering the helper tool.
    public func registerHelperTool() async throws {
        if #available(macOS 13.0, *), let plistName = self.plistName {
            try await self.requestPrivileges([kSMRightModifySystemDaemons], allowUserInteraction: true)

            let daemon = SMAppService.daemon(plistName: plistName)

            if case .enabled = daemon.status {
                try await daemon.unregister()

                // SMAppService errors if we try to register before the previous version has finished unregistering
                for _ in 0..<500 where daemon.status != .notRegistered {
                    try await Task.sleep(for: .microseconds(10))
                }
            }

            try daemon.register()
        } else {
            try await self.requestPrivileges([kSMRightBlessPrivilegedHelper], allowUserInteraction: true)

            _ = try? await self._uninstallHelperTool()
            _ = try? await self.unblessHelperTool()

            try self.blessHelperTool()
        }
    }

    /// Unregister the helper tool.
    /// When using the legacy API, this will also uninstall the helper tool and LaunchDaemons plist from `/Library`.
    ///
    /// - Throws: Any error that occurs in the process of uninstalling or unregistering the helper tool.
    public func unregisterHelperTool() async throws {
        try await self.requestPrivileges([kSMRightModifySystemDaemons], allowUserInteraction: true)

        if #available(macOS 13.0, *), let plistName = self.plistName {
            try await SMAppService.daemon(plistName: plistName).unregister()
        } else {
            try await self._uninstallHelperTool()
            try await self.unblessHelperTool()
        }
        
        try self.revokePrivileges()
    }

    @available(macOS, deprecated: 13.0, message: "Installing is only relevant when using the legacy service management APIs")
    private func _uninstallHelperTool() async throws {
        _ = try await self._executeInHelperTool(
            command: BuiltInCommands.uninstallHelperTool,
            expectedVersion: nil,
            request: XPCNull.shared
        ) as XPCNull
    }

    /// Execute a command in your helper tool that takes no arguments and returns no value.
    ///
    /// - Parameters:
    ///   - command: A `CommandSpec` representing the command to execute in the helper tool.
    ///   - reinstallIfInvalid: If `true`, automatically reinstall the tool if it is not installed properly.
    ///
    /// - Throws:
    ///   - Any error that is thrown by the helper function.
    ///   - Any error that occurs in the process of communicating with the helper.
    ///   - If `reinstallIfInvalid` is true, any error that occurs in the process of reinstalling the helper tool.
    public func executeInHelperTool(command: CommandSpec, reinstallIfInvalid: Bool = true) async throws {
        try await self.executeInHelperTool(
            command: command,
            request: XPCNull.shared,
            reinstallIfInvalid: reinstallIfInvalid
        )
    }

    /// Execute a command in your helper tool that takes an argument but does not returns a value.
    ///
    /// - Parameters:
    ///   - command: A `CommandSpec` representing the command to execute in the helper tool.
    ///   - request: A parameter to send to the helper function. Can be any value that conforms to `Codable`.
    ///   - reinstallIfInvalid: If `true`, automatically reinstall the tool if it is not installed properly.
    ///
    /// - Throws:
    ///   - Any error that is thrown by the helper function.
    ///   - Any error that occurs in the process of communicating with the helper.
    ///   - If `reinstallIfInvalid` is true, any error that occurs in the process of reinstalling the helper tool.
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

    /// Execute a command in your helper tool that takes no arguments but returns a value.
    ///
    /// - Parameters:
    ///   - command: A `CommandSpec` representing the command to execute in the helper tool.
    ///   - reinstallIfInvalid: If `true`, automatically reinstall the tool if it is not installed properly.
    ///
    /// - Returns: The value returned by the helper function.
    ///
    /// - Throws:
    ///   - Any error that is thrown by the helper function.
    ///   - Any error that occurs in the process of communicating with the helper.
    ///   - If `reinstallIfInvalid` is true, any error that occurs in the process of reinstalling the helper tool.
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

    /// Execute a command in your helper tool that takes an argument and returns a value.
    ///
    /// - Parameters:
    ///   - command: A `CommandSpec` representing the command to execute in the helper tool.
    ///   - request: A parameter to send to the helper function. Can be any value that conforms to `Codable`.
    ///   - reinstallIfInvalid: If `true`, automatically reinstall the tool if it is not installed properly.
    ///
    /// - Returns: The value returned by the helper function.
    ///
    /// - Throws:
    ///   - Any error that is thrown by the helper function.
    ///   - Any error that occurs in the process of communicating with the helper.
    ///   - If `reinstallIfInvalid` is true, any error that occurs in the process of reinstalling the helper tool.
    public func executeInHelperTool<Request: Codable, Response: Codable>(
        command: CommandSpec,
        request: Request,
        reinstallIfInvalid: Bool = true
    ) async throws -> Response {
        try validateArguments(command: command, requestType: type(of: request), responseType: Response.self)

        if command == BuiltInCommands.uninstallHelperTool {
            try await self.unregisterHelperTool()
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
                try await self.registerHelperTool()
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
        // Look up the command and preauthorize.  This has the nice side effect that
        // the authentication dialog comes up, in the typical case, here, rather than
        // in the helper tool.
        try await self.requestPrivileges([command.name])

        let connection = try XPCConnection(
            type: .remoteMachService(serviceName: self.helperID, isPrivilegedHelperTool: true)
        )

        let message = try AuthMessage(authorization: self.authorization, expectedVersion: expectedVersion, body: request)

        connection.activate()

        let replyMessage: AuthMessage<Response> = try await connection.sendMessage(name: command.name, request: message)

        return replyMessage.body
    }

    private func requestPrivileges(_ privileges: [String], allowUserInteraction: Bool = true) async throws {
        if privileges.isEmpty { return }

        let authorization = try self.authorization

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

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) -> Void in
            AuthorizationCopyRightsAsync(authorization, &rights, nil, flags) { err, _ in
                switch err {
                case errAuthorizationSuccess:
                    continuation.resume()
                default:
                    continuation.resume(throwing: CFError.make(osStatus: err))
                }
            }
        }
    }

    private func revokePrivileges() throws {
        guard let auth = self._authorization else { return }

        let err = AuthorizationFree(auth, .destroyRights)
        guard err == errAuthorizationSuccess else { throw CFError.make(osStatus: err) }

        self._authorization = nil
    }

    @available(macOS, deprecated: 13.0, message: "Blessing is only relevant when using the legacy service management APIs")
    private func blessHelperTool() throws {
        var smError: Unmanaged<CFError>?
        if !SMJobBless(kSMDomainSystemLaunchd, self.helperID as CFString, try self.authorization, &smError) {
            throw smError?.takeRetainedValue() ?? CocoaError(.fileWriteUnknown)
        }
    }

    @available(macOS, deprecated: 13.0, message: "Blessing is only relevant when using the legacy service management APIs")
    private func unblessHelperTool() async throws {
        var smError: Unmanaged<CFError>? = nil
        // deprecated in macOS 10.10, but the replacement is not available until 13.0.
        // Therefore, kludge around the deprecation warning using dlsym.

        let remove = unsafeBitCast(
            dlsym(UnsafeMutableRawPointer(bitPattern: -1), "SMJobRemove"),
            to: (@convention(c) (CFString?, CFString, AuthorizationRef?, Bool, UnsafeMutablePointer<Unmanaged<CFError>?>?) ->
                 Bool).self
        )

        if !remove(kSMDomainSystemLaunchd, self.helperID as CFString, try self.authorization, true, &smError) {
            throw smError?.takeRetainedValue() ?? CocoaError(.fileWriteUnknown)
        }
    }
}
