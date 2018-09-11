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

    public init(commandSet: CommandSet, bundle: Bundle? = nil, tableName: String? = nil) throws {
        var authRef: AuthorizationRef? = nil
        let err = AuthorizationCreate(nil, nil, [], &authRef)
        if err != errSecSuccess { throw HelperClient.convertOSStatus(err) }
        self.authRef = try authRef ?? { throw CocoaError(.fileReadUnknown) }()
        
        commandSet.setupAuthorizationRights(self.authRef, bundle: bundle, tableName: tableName)
    }
    
    public func authorizationData() throws -> Data {
        var authData = Data(count: MemoryLayout<AuthorizationExternalForm>.size)
        
        let err = authData.withUnsafeMutableBytes { AuthorizationMakeExternalForm(self.authRef, $0) }
        
        if (err != errAuthorizationSuccess) {
            throw HelperClient.convertOSStatus(err)
        }
        
        return authData
    }
    
    public func installHelperTool(helperID: String,
                                  machServiceName: String? = nil,
                                  completionHandler: @escaping (Error?) -> ()) {
        if let machServiceName = machServiceName {
            self.uninstallHelperTool(helperID: helperID, machServiceName: machServiceName) { _ in
                self.blessHelperTool(helperID: helperID, completionHandler: completionHandler)
            }
        } else {
            self.blessHelperTool(helperID: helperID, completionHandler: completionHandler)
        }
    }
    
    private func blessHelperTool(helperID: String, completionHandler: @escaping (Error?) -> ()) {
        var smError: Unmanaged<CFError>? = nil
        if !SMJobBless(kSMDomainSystemLaunchd, helperID as CFString, self.authRef, &smError) {
            completionHandler(HelperClient.convertCFError(smError?.takeRetainedValue()))
        } else {
            completionHandler(nil)
        }
    }
    
    public func uninstallHelperTool(helperID: String,
                                    machServiceName: String,
                                    completionHandler: @escaping (Error?) -> ()) {
        let group = DispatchGroup()
        let sema = DispatchSemaphore(value: 1)
        var err: Error? = nil
        
        do {
            group.enter()
            
            let authData = try self.authorizationData()
            
            let errorHandler: (Error) -> () = {
                sema.wait()
                defer { sema.signal() }
                
                if (err == nil) { err = $0 }
            }
            
            let connectHandler: (BuiltInCommands?) -> () = {
                $0?.uninstallHelperTool(authorizationData: authData) {
                    if let error = $0 {
                        sema.wait()
                        defer { sema.signal() }
                        if (err == nil) { err = error }
                    }
                    
                    group.leave()
                }
            }
            
            self.connectToHelperTool(helperID: helperID,
                                     machServiceName: machServiceName,
                                     protocol:  BuiltInCommands.self,
                                     errorHandler: errorHandler,
                                     connectHandler: connectHandler)
        } catch {
            sema.wait()
            defer { sema.signal() }
            
            if (err == nil) { err = error }
            
            group.leave()
        }
        
        var smError: Unmanaged<CFError>? = nil
        if !SMJobRemove(kSMDomainSystemLaunchd, helperID as CFString, self.authRef, true, &smError) {
            sema.wait()
            defer { sema.signal() }
            
            if (err == nil) {
                err = smError.map { HelperClient.convertCFError($0.takeRetainedValue()) } ??
                    CocoaError(.fileWriteUnknown)
            }
        }
        
        group.notify(queue: .main) {
            completionHandler(err)
        }
    }
    
    public func requestHelperVersion(helperID: String,
                                     machServiceName: String,
                                     completionHandler: @escaping (Result<String>) -> ()) {
        print("this never gets called?")
        
        var err: Error? = nil
        
        let errorHandler: (Error) -> () = {
            if (err == nil) { err = $0 }
        }
        
        let connectHandler: (BuiltInCommands?) -> () = {
            guard let proxy = $0 else {
                completionHandler(.error(err ?? CocoaError(.fileReadUnknown)))
                return
            }
            
            proxy.getVersion() {
                if let error = $1 {
                    print("error: \(error.localizedDescription)")
                    completionHandler(.error(error))
                } else if let version = $0 {
                    print("version is \(version)")
                    completionHandler(.success(version))
                } else {
                    print("something weird happeneD")
                    completionHandler(.error(CocoaError(.fileReadUnknown)))
                }
            }
        }
        
        self.connectToHelperTool(helperID: helperID,
                                 machServiceName: machServiceName,
                                 protocol: BuiltInCommands.self,
                                 errorHandler: errorHandler,
                                 connectHandler: connectHandler)
    }
    
    public func connectToHelperTool<P: BuiltInCommands>(helperID: String,
                                                        machServiceName: String,
                                                        protocol proto: P.Type,
                                                        interface: NSXPCInterface? = nil,
                                                        expectedVersion: String? = nil,
                                                        errorHandler: @escaping (Error) -> (),
                                                        connectHandler: @escaping (P?) -> ()) {
        let proxy: P
        
        do {
            proxy = try self._connectToHelperTool(machServiceName: machServiceName, protocol: proto, interface: interface, errorHandler: errorHandler)
        } catch {
            errorHandler(error)
            connectHandler(nil)
            return
        }
        
        if let expectedVersion = expectedVersion {
            proxy.getVersion() {
                if let version = $0 {
                    if version == expectedVersion {
                        connectHandler(proxy)
                    } else {
                        self.installHelperTool(helperID: helperID, machServiceName: machServiceName) {
                            do {
                                if let error = $0 {
                                    throw error
                                }
                                
                                let newProxy = try self._connectToHelperTool(machServiceName: machServiceName, protocol: proto, interface: interface, errorHandler: errorHandler)
                                
                                connectHandler(newProxy)
                            } catch {
                                errorHandler(error)
                                connectHandler(nil)
                            }
                        }
                    }
                } else {
                    errorHandler($1 ?? CocoaError(.fileReadUnknown))
                    connectHandler(nil)
                }
            }
        } else {
            connectHandler(proxy)
        }
    }
    
    private func _connectToHelperTool<P: BuiltInCommands>(machServiceName: String,
                                                          protocol proto: P.Type,
                                                          interface: NSXPCInterface?,
                                                          errorHandler: @escaping (Error) -> ()) throws -> P {
        let conn = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        
        return try self.getProxy(conn, protocol: proto, interface: interface, errorHandler: errorHandler)
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
        guard let objcProto = proto as Any as AnyObject as? Protocol else {
            throw CocoaError(.fileReadUnknown)
        }
        
        conn.remoteObjectInterface = interface ?? NSXPCInterface(with: objcProto)
        
        conn.resume()
        
        let proxy = conn.remoteObjectProxyWithErrorHandler(errorHandler)
        
        return try proxy as? P ?? { throw CocoaError(.fileReadUnknown) }()
    }
    
    private static func convertOSStatus(_ err: OSStatus) -> Error {
        let unconverted: Error = {
            // Prefer POSIX errors over OSStatus ones if possible, as they tend to present
            // nicer error messages to the end user.
            
            if (errSecErrnoBase...errSecErrnoLimit).contains(err) {
                // Return NSError rather than POSIXError simply to avoid the optional code parameter
                return NSError(domain: NSPOSIXErrorDomain, code: Int(err - errSecErrnoBase), userInfo: nil)
            } else {
                var userInfo: [String : Any] = [:]
                
                if let errStr = SecCopyErrorMessageString(err, nil) {
                    userInfo[NSLocalizedFailureReasonErrorKey] = errStr as String
                }
                
                return NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: userInfo)
            }
        }()
        
        return self.convertError(unconverted)
    }
    
    private static func convertCFError(_ cfError: CFError?) -> Error {
        if let err = cfError.map({ unsafeBitCast($0, to: NSError.self) }) {
            return self.convertError(err)
        } else {
            return CocoaError(.fileReadUnknown)
        }
    }
    
    private static func convertError(_ error: Error) -> Error {
        // Cocoa tends to do a nicer job presenting Cocoa errors than POSIX or OSStatus ones,
        // particularly with NSUserCancelledError, in which case -presentError: will skip
        // showing the error altogether. For certain other error types, using the Cocoa domain
        // will provide a little more information, including, sometimes, the filename for which
        // the operation failed. Therefore, convert errors to NSCocoaErrorDomain when possible.
        
        let code: CocoaError.Code? = {
            if let posix = error as? POSIXError {
                return CocoaError.Code(errno: posix.code.rawValue)
            } else if (error as NSError).domain == NSOSStatusErrorDomain {
                return CocoaError.Code(osStatus: OSStatus((error as NSError).code))
            } else {
                return nil
            }
        }()
        
        if let code = code {
            var userInfo = (error as NSError).userInfo
            
            userInfo[NSUnderlyingErrorKey] = error
            
            // Use the built-in error messages instead
            userInfo[NSLocalizedFailureReasonErrorKey] = nil
            
            return CocoaError(code, userInfo: userInfo)
        } else {
            return error
        }
    }
}

extension CocoaError.Code {
    fileprivate init?(errno err: Int32) {
        switch err {
        case ECANCELED:
            self = .userCancelled
        case ENOENT:
            self = .fileNoSuchFile
        case EFBIG:
            self = .fileReadTooLarge
        case EEXIST:
            self = .fileWriteFileExists
        case ENOSPC:
            self = .fileWriteOutOfSpace
        case EROFS:
            self = .fileWriteVolumeReadOnly
        default:
            return nil
        }
    }
    
    fileprivate init?(osStatus err: OSStatus) {
        if (errSecErrnoBase...errSecErrnoLimit).contains(err),
            let code = CocoaError.Code(errno: err - errSecErrnoBase) {
            self = code
            return
        }
        
        switch Int(err) {
        case userCanceledErr, Int(errAuthorizationCanceled), errAEWaitCanceled, kernelCanceledErr, kOTCanceledErr, kECANCELErr, errIACanceled, kRAConnectionCanceled, kTXNUserCanceledOperationErr, kFBCindexingCanceled, kFBCaccessCanceled, kFBCsummarizationCanceled:
            self = .userCancelled
        case fnfErr:
            self = .fileNoSuchFile
        case fileBoundsErr, fsDataTooBigErr:
            self = .fileReadTooLarge
        case dupFNErr:
            self = .fileWriteFileExists
        case dskFulErr, errFSNotEnoughSpaceForOperation:
            self = .fileWriteOutOfSpace
        case vLckdErr:
            self = .fileWriteVolumeReadOnly
        default:
            return nil
        }
    }
}
