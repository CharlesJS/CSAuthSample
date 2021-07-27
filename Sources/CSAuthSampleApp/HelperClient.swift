//
//  HelperClient.swift
//  App Library
//
//  Created by Charles Srstka on 6/25/18.
//

import CSAuthSampleCommon
import Foundation
import ServiceManagement
import System

/// The primary class used by your application to communicate with your helper tool.
///
/// To use, create an instance and use `connectToHelperTool` to send messages to the helper tool.
public class HelperClient<CommandType: Command> {
    let helperID: String
    private let authorization: AuthorizationRef

    /// Create a `HelperClient` object.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - authData: Authorization data, in the format of an `AuthorizationExternalForm`. If not provided, a new `AuthorizationRef` will be created.
    ///   - commandSet: A `CommandSet` object describing the messages the helper accepts, and their required authorization levels.
    ///   - bundle: A bundle containing a strings table containing localized messages to present to the user. Optional.
    ///   - tableName: The name of a strings table containing localized messages to present to the user. Optional.
    /// - Throws: Any errors that occur in the process of creating the `HelperClient`'s internal `AuthorizationRef`.
    public init(
        helperID: String,
        authorization: AuthorizationRef? = nil,
        commandType: CommandType.Type,
        bundle: Bundle? = nil,
        tableName: String? = nil
    ) throws {
        self.helperID = helperID

        self.authorization = try authorization ?? {
            var authorization: AuthorizationRef?
            let err = AuthorizationCreate(nil, nil, [], &authorization)
            if err != errAuthorizationSuccess { throw convertOSStatusError(err) }

            return try authorization ?? { throw CocoaError(.fileReadUnknown) }()
        }()

        let cfBundle = bundle == .main ? CFBundleGetMainBundle() : bundle.flatMap {
            CFBundleCreate(kCFAllocatorDefault, $0.bundleURL as CFURL)
        }

        try commandType.setUpAccessRights(authorization: self.authorization, bundle: cfBundle, tableName: tableName)
    }

    deinit {
        AuthorizationFree(self.authorization, .destroyRights)
    }

    /// Get the version of the helper tool.
    ///
    /// This is helpful for making sure that the application and helper tool are in sync with each other.
    /// If the helper's version does not match the app's version, it is generally a sign that the helper needs to be upgraded.
    public func requestHelperVersion() async throws -> String {
        let response = try await self.executeInHelperTool(command: BuiltInCommands.getVersion)

        guard let version = response[kCFBundleVersionKey as String] as? String else {
            throw Errno.badFileTypeOrFormat
        }

        return version
    }

    /// Install the helper tool.
    public func installHelperTool() async throws {
        _ = try? await self.uninstallHelperTool()

        try self.requestPrivileges([kSMRightBlessPrivilegedHelper], allowUserInteraction: true)
        try self.blessHelperTool()
    }

    /// Uninstall the helper tool.
    public func uninstallHelperTool() async throws {
        try await self._executeInHelperTool(command: BuiltInCommands.uninstallHelperTool)
        try self.unblessHelperTool()
    }

    @discardableResult
    public func executeInHelperTool(
        command: Command,
        request: [String : Any] = [:],
        reinstallIfInvalid: Bool = true
    ) async throws -> [String : Any] {
        do {
            return try await self._executeInHelperTool(command: command, request: request)
        } catch ConnectionError.connectionInvalid where reinstallIfInvalid {
            print("connection invalid! Reconnecting")
            try await self.installHelperTool()
            return try await self._executeInHelperTool(command: command, request: request)
        }
    }

    @discardableResult
    private func _executeInHelperTool(command: Command, request: [String : Any] = [:]) async throws -> [String : Any] {
        try self.preauthorize(command: command)

        let connection = xpc_connection_create_mach_service(
            self.helperID,
            nil,
            UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED)
        )

        var connectionError: ConnectionError? =  nil
        xpc_connection_set_event_handler(connection) { event in
            if connectionError != nil { return }

            switch xpc_get_type(event) {
            case XPC_TYPE_ERROR:
                if event === XPC_ERROR_CONNECTION_INTERRUPTED {
                    connectionError = .connectionInterrupted
                } else if event === XPC_ERROR_CONNECTION_INVALID {
                    connectionError = .connectionInvalid
                } else {
                    connectionError = .unexpectedConnection
                }
            default:
                connectionError = .unexpectedEvent
            }
        }

        xpc_connection_resume(connection)

        let message = xpc_dictionary_create(nil, nil, 0)

        try self.addAuthorizationData(to: message)

        xpc_dictionary_set_string(message, DictionaryKeys.commandName, command.name)

        if !request.isEmpty, let xpcRequest = (request as CFDictionary).toXPCObject() {
            xpc_dictionary_set_value(message, DictionaryKeys.request, xpcRequest)
        }

        return try await withCheckedThrowingContinuation { continuation in
            xpc_connection_send_message_with_reply(connection, message, nil) { reply in
                do {
                    if let error = connectionError { throw error }

                    continuation.resume(returning: try self.handleXPCReply(reply))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func preauthorize(command: Command) throws {
        // Look up the command and preauthorize.  This has the nice side effect that
        // the authentication dialog comes up, in the typical case, here, rather than
        // in the helper tool.

        try command.name.withCString {
            var item = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)

            try withUnsafeMutablePointer(to: &item) {
                var rights = AuthorizationRights(count: 1, items: $0)

                let err = AuthorizationCopyRights(
                    self.authorization,
                    &rights,
                    nil,
                    [.extendRights, .interactionAllowed, .preAuthorize],
                    nil
                )

                guard err == errAuthorizationSuccess else { throw convertOSStatusError(err) }
            }
        }
    }

    private func addAuthorizationData(to dictionary: xpc_object_t) throws {
        var extAuth = AuthorizationExternalForm()
        let err = AuthorizationMakeExternalForm(self.authorization, &extAuth)

        guard err == errAuthorizationSuccess else { throw convertOSStatusError(err) }

        xpc_dictionary_set_data(
            dictionary,
            DictionaryKeys.authData,
            &extAuth,
            MemoryLayout<AuthorizationExternalForm>.size
        )
    }

    private func handleXPCReply(_ reply: xpc_object_t) throws -> [String : Any] {
        guard let response = xpc_dictionary_get_value(reply, DictionaryKeys.response) as? [String : Any] else {
            if let err = xpc_dictionary_get_value(reply, DictionaryKeys.error) as? Error {
                throw err
            } else {
                throw CocoaError(.fileReadUnknown)
            }
        }

        return response
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
        let err = AuthorizationCopyRights(self.authorization, &rights, nil, flags, nil)
        guard err == errAuthorizationSuccess else { throw convertOSStatusError(err) }
    }

    private func blessHelperTool() throws {
        var smError: Unmanaged<CFError>?
        if !SMJobBless(kSMDomainSystemLaunchd, self.helperID as CFString, self.authorization, &smError) {
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

        if !remove(kSMDomainSystemLaunchd, self.helperID as CFString, self.authorization, true, &smError) {
            throw smError?.takeRetainedValue() ?? CocoaError(.fileWriteUnknown)
        }
    }
}
