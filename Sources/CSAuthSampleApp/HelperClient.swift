//
//  HelperClient.swift
//  App Library
//
//  Created by Charles Srstka on 6/25/18.
//

import Foundation
import ServiceManagement
import CSAuthSampleCommon

public struct HelperClient {
    private let authRef: AuthorizationRef

    public init(authData: Data? = nil, commandSet: CommandSet, bundle: Bundle? = nil, tableName: String? = nil) throws {
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

    public func uninstallHelperTool(helperID: String, completionHandler: @escaping (Error?) -> Void) {
        do {
            let authData = try self.authorizationData()

            let errorHandler: (Error) -> Void = { completionHandler($0) }

            let connectionHandler: (BuiltInCommands) -> Void = { proxy in
                proxy.uninstallHelperTool(authorizationData: authData) { completionHandler($0) }
            }

            self.connectToHelperTool(helperID: helperID,
                                     protocol: BuiltInCommands.self,
                                     installIfNecessary: false,
                                     errorHandler: errorHandler,
                                     connectionHandler: connectionHandler)
        } catch {
            completionHandler(error)
        }
    }

    public func requestHelperVersion(helperID: String, completionHandler: @escaping (Result<String, Error>) -> Void) {
        let conn: NSXPCConnection

        do {
            conn = try self._openConnection(helperID: helperID, interface: nil, protocol: BuiltInCommands.self)
        } catch {
            completionHandler(.failure(error))
            return
        }

        self.checkHelperVersion(connection: conn, completionHandler: completionHandler)
    }

    public func connectToHelperTool<P: BuiltInCommands>(helperID: String,
                                                        protocol proto: P.Type,
                                                        interface: NSXPCInterface? = nil,
                                                        expectedVersion: String? = nil,
                                                        installIfNecessary: Bool = true,
                                                        errorHandler: @escaping (Error) -> Void,
                                                        connectionHandler: @escaping (P) -> Void) {
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
                case let .success(version) where version == expectedVersion:
                    self._connectToHelperTool(connection: conn,
                                              protocol: proto,
                                              interface: interface,
                                              errorHandler: errorHandler,
                                              connectionHandler: connectionHandler)
                case .failure where installIfNecessary, .success where installIfNecessary:
                    self._installAndConnect(helperID: helperID,
                                            protocol: proto,
                                            interface: interface,
                                            errorHandler: errorHandler,
                                            connectionHandler: connectionHandler)
                case let .failure(error) where !installIfNecessary:
                    errorHandler(error)
                default:
                    errorHandler(CocoaError(.fileReadUnknown))
                }
            }
        } else {
            self._connectToHelperTool(connection: conn,
                                      protocol: proto,
                                      interface: interface,
                                      errorHandler: errorHandler,
                                      connectionHandler: connectionHandler)
        }
    }

    public func connectViaEndpoint<P: BuiltInCommands>(_ endpoint: NSXPCListenerEndpoint,
                                                       protocol proto: P.Type,
                                                       interface: NSXPCInterface? = nil,
                                                       errorHandler: @escaping (Error) -> Void) throws -> P {
        let conn = NSXPCConnection(listenerEndpoint: endpoint)

        return try self.getProxy(conn, protocol: proto, interface: interface, errorHandler: errorHandler)
    }

    private func getProxy<P: BuiltInCommands>(_ conn: NSXPCConnection,
                                              protocol proto: P.Type,
                                              interface: NSXPCInterface?,
                                              errorHandler: @escaping (Error) -> Void) throws -> P {
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

        /* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
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

    private func _installAndConnect<P: BuiltInCommands>(helperID: String,
                                                        protocol proto: P.Type,
                                                        interface: NSXPCInterface?,
                                                        errorHandler: @escaping (Error) -> Void,
                                                        connectionHandler: @escaping (P) -> Void) {
        self.installHelperTool(helperID: helperID) {
            if let error = $0 {
                errorHandler(error)
                return
            }

            self.connectToHelperTool(helperID: helperID,
                                     protocol: proto,
                                     interface: interface,
                                     expectedVersion: nil,
                                     installIfNecessary: false,
                                     errorHandler: errorHandler,
                                     connectionHandler: connectionHandler)
        }
    }

    private func _openConnection<P: BuiltInCommands>(helperID: String,
                                                     interface: NSXPCInterface?,
                                                     protocol proto: P.Type) throws -> NSXPCConnection {
        guard let objcProto = proto as Any as AnyObject as? Protocol else {
            throw CocoaError(.fileReadUnknown)
        }

        let conn = NSXPCConnection(machServiceName: helperID, options: .privileged)

        conn.remoteObjectInterface = interface ?? NSXPCInterface(with: objcProto)
        conn.resume()

        return conn
    }

    private func _connectToHelperTool<P: BuiltInCommands>(connection conn: NSXPCConnection,
                                                          protocol proto: P.Type,
                                                          interface: NSXPCInterface?,
                                                          errorHandler: @escaping (Error) -> Void,
                                                          connectionHandler: @escaping (P) -> Void) {
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
