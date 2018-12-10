//
//  HelperClient.swift
//  App Library (ObjC Helper)
//
//  Created by Charles Srstka on 6/25/18.
//

import Foundation
import ServiceManagement
import CSASCommon

public struct HelperClient {
    private let authRef: AuthorizationRef

    public init(authData: Data? = nil, commandSet: CommandSet, bundle: Bundle? = nil, tableName: String? = nil) throws {
        if let data = authData {
            self.authRef = try data.withUnsafeBytes { (extForm: UnsafePointer<AuthorizationExternalForm>) -> AuthorizationRef in
                var authRef: AuthorizationRef? = nil
                
                let err = AuthorizationCreateFromExternalForm(extForm, &authRef)
                if err != errSecSuccess { throw ConvertOSStatus(err) }
                
                return try authRef ?? { throw CocoaError(.fileReadUnknown) }()
            }
        } else {
            var authRef: AuthorizationRef? = nil
            let err = AuthorizationCreate(nil, nil, [], &authRef)
            if err != errSecSuccess { throw ConvertOSStatus(err) }
            self.authRef = try authRef ?? { throw CocoaError(.fileReadUnknown) }()
        }
        
        commandSet.setupAuthorizationRights(self.authRef, bundle: bundle, tableName: tableName)
    }
    
    public func authorizationData() throws -> Data {
        var authData = Data(count: MemoryLayout<AuthorizationExternalForm>.size)
        
        let err = authData.withUnsafeMutableBytes { AuthorizationMakeExternalForm(self.authRef, $0) }
        
        if (err != errAuthorizationSuccess) {
            throw ConvertOSStatus(err)
        }
        
        return authData
    }
    
    public func installHelperTool(helperID: String, completionHandler: @escaping (Error?) -> ()) {
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
    
    public func uninstallHelperTool(helperID: String, completionHandler: @escaping (Error?) -> ()) {
        let sema = DispatchSemaphore(value: 1)
        var alreadyReturned = false
        
        do {
            let authData = try self.authorizationData()
            
            let errorHandler: (Error) -> () = {
                sema.wait()
                defer { sema.signal() }
                
                if alreadyReturned {
                    return
                }
                
                alreadyReturned = true
                completionHandler($0)
            }
            
            let connectionHandler: (BuiltInCommands) -> () = { proxy in
                proxy.uninstallHelperTool(authorizationData: authData) {
                    sema.wait()
                    defer { sema.signal() }
                    
                    if alreadyReturned {
                        return
                    }
                    
                    alreadyReturned = true
                    completionHandler($0)
                }
            }
            
            self.connectToHelperTool(helperID: helperID,
                                     protocol:  BuiltInCommands.self,
                                     installIfNecessary: false,
                                     errorHandler: errorHandler,
                                     connectionHandler: connectionHandler)
        } catch {
            completionHandler(error)
        }
    }
    
    public func requestHelperVersion(helperID: String, completionHandler: @escaping (Result<String>) -> ()) {
        let conn: NSXPCConnection
            
        do {
            conn = try self._openConnection(helperID: helperID, interface: nil, protocol: BuiltInCommands.self)
        } catch {
            completionHandler(.error(error))
            return
        }
        
        self.checkHelperVersion(connection: conn, completionHandler: completionHandler)
    }
    
    public func connectToHelperTool<P: BuiltInCommands>(helperID: String,
                                                        protocol proto: P.Type,
                                                        interface: NSXPCInterface? = nil,
                                                        expectedVersion: String? = nil,
                                                        installIfNecessary: Bool = true,
                                                        errorHandler: @escaping (Error) -> (),
                                                        connectionHandler: @escaping (P) -> ()) {
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
                case .error where installIfNecessary, .success where installIfNecessary:
                    self._installAndConnect(helperID: helperID,
                                            protocol: proto,
                                            interface: interface,
                                            errorHandler: errorHandler,
                                            connectionHandler: connectionHandler)
                case let .error(error) where !installIfNecessary:
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
                                                       errorHandler: @escaping (Error) -> ()) throws -> P {
        let conn = NSXPCConnection(listenerEndpoint: endpoint)
        
        return try self.getProxy(conn, protocol: proto, interface: interface, errorHandler: errorHandler)
    }
    
    private func getProxy<P: BuiltInCommands>(_ conn: NSXPCConnection,
                                              protocol proto: P.Type,
                                              interface: NSXPCInterface?,
                                              errorHandler: @escaping (Error) -> ()) throws -> P {
        let proxy = conn.remoteObjectProxyWithErrorHandler(errorHandler)
        
        return try proxy as? P ?? { throw CocoaError(.fileReadUnknown) }()
    }
    
    private func requestPrivileges(_ privs: [String], allowUserInteraction: Bool = true) throws {
        if privs.isEmpty {
            return
        }
        
        let items = UnsafeMutablePointer<AuthorizationItem>.allocate(capacity: privs.count)
        
        for (i, eachPriv) in privs.enumerated() {
            let name: UnsafePointer<Int8> = eachPriv.withCString {
                let len = strlen($0) + 1
                let copy = UnsafeMutablePointer<Int8>.allocate(capacity: len)
                copy.initialize(from: $0, count: len)
                
                return UnsafePointer(copy)
            }
            
            items[i] = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
        }
        
        defer {
            for i in 0..<privs.count {
                items[i].name.deallocate()
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
    
    private func blessHelperTool(helperID: String, completionHandler: @escaping (Error?) -> ()) {
        var smError: Unmanaged<CFError>? = nil
        if !SMJobBless(kSMDomainSystemLaunchd, helperID as CFString, self.authRef, &smError) {
            completionHandler(smError.map { ConvertCFError($0.takeRetainedValue()) } ?? CocoaError(.fileWriteUnknown))
        } else {
            completionHandler(nil)
        }
    }
    
    private func _installAndConnect<P: BuiltInCommands>(helperID: String,
                                                        protocol proto: P.Type,
                                                        interface: NSXPCInterface?,
                                                        errorHandler: @escaping (Error) -> (),
                                                        connectionHandler: @escaping (P) -> ()) {
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
                                                          errorHandler: @escaping (Error) -> (),
                                                          connectionHandler: @escaping (P) -> ()) {
        do {
            let proxy = try self.getProxy(conn, protocol: proto, interface: interface, errorHandler: errorHandler)
            connectionHandler(proxy)
        } catch {
            errorHandler(error)
        }
    }
    
    private func checkHelperVersion(connection: NSXPCConnection, completionHandler: @escaping (Result<String>) -> ()) {
        let sema = DispatchSemaphore(value: 1)
        var alreadyReturned = false
        
        let errorHandler: (Error) -> () = { error in
            print("get error")
            sema.wait()
            defer { sema.signal() }
            
            if alreadyReturned {
                return
            }
            
            alreadyReturned = true
            completionHandler(.error(error))
        }
        
        guard let proxy = connection.remoteObjectProxyWithErrorHandler(errorHandler) as? BuiltInCommands else {
            completionHandler(.error(CocoaError(.fileReadUnknown)))
            return
        }
        
        proxy.getVersion() {
            sema.wait()
            defer { sema.signal() }
            
            if alreadyReturned {
                return
            }
            
            alreadyReturned = true
            
            if let error = $1 {
                completionHandler(.error(error))
            } else if let version = $0 {
                completionHandler(.success(version))
            } else {
                completionHandler(.error(CocoaError(.fileReadUnknown)))
            }
        }
    }
}
