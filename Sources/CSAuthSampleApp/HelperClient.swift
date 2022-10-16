//
//  HelperClient.swift
//  App Library
//
//  Created by Charles Srstka on 6/25/18.
//

import CSAuthSampleCommon
import Foundation
import ServiceManagement

/// The primary class used by your application to communicate with your helper tool.
///
/// To use, create an instance and use `connectToHelperTool` to send messages to the helper tool.
public struct HelperClient {
    private let authRef: AuthorizationRef

    /// Create a `HelperClient` object.
    ///
    /// - Parameters:
    ///   - authData: Authorization data, in the format of an `AuthorizationExternalForm`. If not provided, a new `AuthorizationRef` will be created.
    ///   - commandSet: A `CommandSet` object describing the messages the helper accepts, and their required authorization levels.
    ///   - bundle: A bundle containing a strings table containing localized messages to present to the user. Optional.
    ///   - tableName: The name of a strings table containing localized messages to present to the user. Optional.
    /// - Throws: Any errors that occur in the process of creating the `HelperClient`'s internal `AuthorizationRef`.
    public init(
        authData: Data? = nil, commandSet: CommandSet, bundle: Bundle? = nil, tableName: String? = nil
    ) throws {
        if let data = authData {
            self.authRef = try data.withUnsafeBytes {
                guard let extForm = $0.bindMemory(to: AuthorizationExternalForm.self).baseAddress else {
                    throw CocoaError(.fileReadUnknown)
                }

                var authRef: AuthorizationRef?

                let err = AuthorizationCreateFromExternalForm(extForm, &authRef)
                if err != errSecSuccess { throw ConvertOSStatus(err) }

                return try authRef ?? { throw CocoaError(.fileReadUnknown) }()
            }
        } else {
            var authRef: AuthorizationRef?
            let err = AuthorizationCreate(nil, nil, [], &authRef)
            if err != errSecSuccess { throw ConvertOSStatus(err) }
            self.authRef = try authRef ?? { throw CocoaError(.fileReadUnknown) }()
        }

        commandSet.setupAuthorizationRights(self.authRef, bundle: bundle, tableName: tableName)
    }

    /// Generate authorization data.
    ///
    /// It is generally recommended to send this to the helper tool, in order to establish the identity of the sender and prevent message spoofing.
    ///
    /// - Throws: Any error that occurs while generating the authorization data.
    /// - Returns: A `Data` object containing the authorization data, in the format used by `AuthorizationExternalForm`.
    public func authorizationData() throws -> Data {
        var authData = Data(count: MemoryLayout<AuthorizationExternalForm>.size)

        try authData.withUnsafeMutableBytes {
            guard let ptr = $0.bindMemory(to: AuthorizationExternalForm.self).baseAddress else {
                throw CocoaError(.fileReadUnknown)
            }

            let err = AuthorizationMakeExternalForm(self.authRef, ptr)

            if err != errAuthorizationSuccess {
                throw ConvertOSStatus(err)
            }
        }

        return authData
    }

    /// Install the helper tool.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - completionHandler: Reports on the success or failure of the installation.
    public func installHelperTool(helperID: String, completionHandler: @escaping (Error?) -> Void) {
        do {
            try self.requestPrivileges([kSMRightBlessPrivilegedHelper], allowUserInteraction: true)
        } catch {
            completionHandler(error)
            return
        }

        self.uninstallHelperTool(helperID: helperID) { _ in
            self.blessHelperTool(helperID: helperID, completionHandler: completionHandler)
        }
    }

    /// Uninstall the helper tool.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - completionHandler: Reports on the success or failure of the uninstallation.
    public func uninstallHelperTool(helperID: String, completionHandler: @escaping (Error?) -> Void) {
        do {
            let authData = try self.authorizationData()

            let errorHandler: (Error) -> Void = { completionHandler($0) }

            let connectionHandler: (BuiltInCommands) -> Void = { proxy in
                proxy.uninstallHelperTool(authorizationData: authData) { uninstallResult in
                    self.unblessHelperTool(helperID: helperID) {
                        completionHandler(uninstallResult ?? $0)
                    }
                }
            }

            self.connectToHelperTool(
                helperID: helperID,
                protocol: BuiltInCommands.self,
                installIfNecessary: false,
                errorHandler: errorHandler,
                connectionHandler: connectionHandler
            )
        } catch {
            completionHandler(error)
        }
    }

    /// Get the version of the helper tool.
    ///
    /// This is helpful for making sure that the application and helper tool are in sync with each other.
    /// If the helper's version does not match the app's version, it is generally a sign that the helper needs to be upgraded.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - completionHandler: If successful, returns the version of the helper tool.
    public func requestHelperVersion(
        helperID: String, completionHandler: @escaping (Result<String, Error>) -> Void
    ) {
        let conn: NSXPCConnection

        do {
            conn = try self._openConnection(
                helperID: helperID, interface: nil, protocol: BuiltInCommands.self)
        } catch {
            completionHandler(.failure(error))
            return
        }

        self.checkHelperVersion(connection: conn, completionHandler: completionHandler)
    }

    /// Send a message to the helper tool, and receive a notification on getting its reply.
    ///
    /// - Parameters:
    ///   - helperID: The bundle identifier of your helper tool, which should generally be distinct from your main application's bundle identifier.
    ///   - proto: A protocol describing the messages the helper tool accepts. Must conform to `BuiltInCommands`.
    ///   - interface: An optional `NSXPCInterface` describing the helper's interface. If not provided, this will be generated from the `protocol`.
    ///   - expectedVersion: The expected version of the helper. Optional.
    ///   - installIfNecessary: Ignored unless `expectedVersion` is provided. If true, the helper tool will be installed if it is not present, or if its version does not match the expected version.
    ///   - errorHandler: A closure which will be invoked in the event of an error occurring while communicating wth the helper tool.
    ///   - connectionHandler: A closure which will be invoked upon establishing a successful connection to the helper tool.
    public func connectToHelperTool<P: BuiltInCommands>(
        helperID: String,
        protocol proto: P.Type,
        interface: NSXPCInterface? = nil,
        expectedVersion: String? = nil,
        installIfNecessary: Bool = true,
        errorHandler: @escaping (Error) -> Void,
        connectionHandler: @escaping (P) -> Void
    ) {
        let conn: NSXPCConnection

        do {
            conn = try self._openConnection(helperID: helperID, interface: interface, protocol: proto)
        } catch {
            errorHandler(error)
            return
        }

        if let expectedVersion = expectedVersion {
            self.checkHelperVersion(connection: conn) {
                switch $0 {
                case .success(let version) where version == expectedVersion:
                    self._connectToHelperTool(
                        connection: conn,
                        protocol: proto,
                        interface: interface,
                        errorHandler: errorHandler,
                        connectionHandler: connectionHandler)
                case .failure where installIfNecessary, .success where installIfNecessary:
                    self._installAndConnect(
                        helperID: helperID,
                        protocol: proto,
                        interface: interface,
                        errorHandler: errorHandler,
                        connectionHandler: connectionHandler)
                case .failure(let error) where !installIfNecessary:
                    errorHandler(error)
                default:
                    errorHandler(CocoaError(.fileReadUnknown))
                }
            }
        } else {
            self._connectToHelperTool(
                connection: conn,
                protocol: proto,
                interface: interface,
                errorHandler: errorHandler,
                connectionHandler: connectionHandler
            )
        }
    }

    /// Establish a connection via an `NSXPCListenerEndpoint` passed by the helper tool.
    ///
    /// This can sometimes be useful if more advanced communication between the app and the helper tool is needed.
    /// - Parameters:
    ///   - endpoint: The `NSXPCListenerEndpoint` from which to establish a connection.
    ///   - proto: A protocol describing the messages the helper tool accepts. Must conform to `BuiltInCommands`.
    ///   - interface: An optional `NSXPCInterface` describing the helper's interface. If not provided, this will be generated from the `protocol`.
    ///   - errorHandler: A closure which will be invoked in the event of an error occurring while communicating wth the helper tool.
    /// - Throws: Any errors that occur in the process of establishing communication with the helper tool.
    /// - Returns: An proxy object, conforming to `proto`, which can be used to send messages to the helper tool.
    public func connectViaEndpoint<P: BuiltInCommands>(
        _ endpoint: NSXPCListenerEndpoint,
        protocol proto: P.Type,
        interface: NSXPCInterface? = nil,
        errorHandler: @escaping (Error) -> Void
    ) throws -> P {
        let conn = NSXPCConnection(listenerEndpoint: endpoint)

        return try self.getProxy(conn, protocol: proto, interface: interface, errorHandler: errorHandler)
    }

    private func getProxy<P: BuiltInCommands>(
        _ conn: NSXPCConnection,
        protocol proto: P.Type,
        interface: NSXPCInterface?,
        errorHandler: @escaping (Error) -> Void
    ) throws -> P {
        let proxy = conn.remoteObjectProxyWithErrorHandler(errorHandler)

        return try proxy as? P ?? { throw CocoaError(.fileReadUnknown) }()
    }

    private func requestPrivileges(_ privs: [String], allowUserInteraction: Bool = true) throws {
        if privs.isEmpty {
            return
        }

        let items = UnsafeMutablePointer<AuthorizationItem>.allocate(capacity: privs.count)

        for (index, eachPriv) in privs.enumerated() {
            let name: UnsafePointer<Int8> = eachPriv.withCString {
                let len = strlen($0) + 1
                let copy = UnsafeMutablePointer<Int8>.allocate(capacity: len)
                copy.initialize(from: $0, count: len)

                return UnsafePointer(copy)
            }

            items[index] = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        }

        defer {
            for index in 0..<privs.count {
                items[index].name.deallocate()
            }

            items.deallocate()
        }

        var rights = AuthorizationRights(count: UInt32(privs.count), items: items)

        var flags: AuthorizationFlags = [.preAuthorize, .extendRights]
        if allowUserInteraction {
            flags.insert(.interactionAllowed)
        }

        // Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper).
        let status = AuthorizationCopyRights(authRef, &rights, nil, flags, nil)

        if status != errAuthorizationSuccess {
            throw ConvertOSStatus(status)
        }
    }

    private func blessHelperTool(helperID: String, completionHandler: @escaping (Error?) -> Void) {
        var smError: Unmanaged<CFError>?
        if !SMJobBless(kSMDomainSystemLaunchd, helperID as CFString, self.authRef, &smError) {
            completionHandler(smError.map { ConvertCFError($0.takeRetainedValue()) } ?? CocoaError(.fileWriteUnknown))
        } else {
            completionHandler(nil)
        }
    }
    
    private func unblessHelperTool(helperID: String, completionHandler: @escaping (Error?) -> Void) {
        var smError: Unmanaged<CFError>? = nil
        // deprecated, but there is still not a decent replacement, so 🤷
        // use some rather unfortunate hackery with dlsym to get around deprecation warning

        guard let smJobRemoveSym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "SMJobRemove") else {
            completionHandler(CocoaError(.fileWriteUnknown))
            return
        }

        let smJobRemove = unsafeBitCast(smJobRemoveSym, to: (@convention(c) (CFString?, CFString, AuthorizationRef?, Bool, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool).self)

        guard smJobRemove(kSMDomainSystemLaunchd, helperID as CFString, self.authRef, true, &smError) else {
            completionHandler(smError.map { ConvertCFError($0.takeRetainedValue()) } ?? CocoaError(.fileWriteUnknown))
            return
        }

        completionHandler(nil)
    }

    private func _installAndConnect<P: BuiltInCommands>(
        helperID: String,
        protocol proto: P.Type,
        interface: NSXPCInterface?,
        errorHandler: @escaping (Error) -> Void,
        connectionHandler: @escaping (P) -> Void
    ) {
        self.installHelperTool(helperID: helperID) {
            if let error = $0 {
                errorHandler(error)
                return
            }

            self.connectToHelperTool(
                helperID: helperID,
                protocol: proto,
                interface: interface,
                expectedVersion: nil,
                installIfNecessary: false,
                errorHandler: errorHandler,
                connectionHandler: connectionHandler
            )
        }
    }

    private func _openConnection<P: BuiltInCommands>(
        helperID: String,
        interface: NSXPCInterface?,
        protocol proto: P.Type
    ) throws -> NSXPCConnection {
        guard let objcProto = proto as Any as AnyObject as? Protocol else {
            throw CocoaError(.fileReadUnknown)
        }

        let conn = NSXPCConnection(machServiceName: helperID, options: .privileged)

        conn.remoteObjectInterface = interface ?? NSXPCInterface(with: objcProto)
        conn.resume()

        return conn
    }

    private func _connectToHelperTool<P: BuiltInCommands>(
        connection conn: NSXPCConnection,
        protocol proto: P.Type,
        interface: NSXPCInterface?,
        errorHandler: @escaping (Error) -> Void,
        connectionHandler: @escaping (P) -> Void
    ) {
        do {
            let proxy = try self.getProxy(conn, protocol: proto, interface: interface, errorHandler: errorHandler)
            connectionHandler(proxy)
        } catch {
            errorHandler(error)
        }
    }

    private func checkHelperVersion(
        connection: NSXPCConnection,
        completionHandler: @escaping (Result<String, Error>) -> Void
    ) {
        let errorHandler: (Error) -> Void = { completionHandler(.failure($0)) }

        guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler) as? BuiltInCommands else {
            completionHandler(.failure(CocoaError(.fileReadUnknown)))
            return
        }

        proxy.getVersion {
            if let error = $1 {
                completionHandler(.failure(error))
            } else if let version = $0 {
                completionHandler(.success(version))
            } else {
                completionHandler(.failure(CocoaError(.fileReadUnknown)))
            }
        }
    }
}
