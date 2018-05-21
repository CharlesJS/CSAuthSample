// CSAuthSampleAppLib.swift
// Copyright Charles Srstka, 2013-2018.
// Based on "BetterAuthorizationSampleLib.c" by Apple Computer.

import Foundation
import CSAuthSampleCommon
import ServiceManagement

public class CSASRequestSender {
    public enum Result<T> {
        case success(T)
        case error(Error)
        
        public func unwrap() throws -> T {
            switch self {
            case let .success(ret):
                return ret
            case let .error(error):
                throw error
            }
        }
    }
    
    public class PersistentConnection {
        public private(set) var isValid: Bool
        
        private var connection: xpc_connection_t?
        private var connectionError: Error?
        
        fileprivate init(xpcConnection: xpc_connection_t) {
            self.connection = xpcConnection
            self.isValid = true
            
            xpc_connection_set_event_handler(xpcConnection) { event in
                switch xpc_get_type(event) {
                case XPC_TYPE_ERROR:
                    if self.connectionError == nil { self.connectionError = event.error }
                    
                    if event === XPC_ERROR_CONNECTION_INVALID || event === XPC_ERROR_CONNECTION_INTERRUPTED {
                        self.close()
                    }
                default:
                    if self.connectionError == nil {
                        self.connectionError = CSASError.unexpectedEvent
                    }
                }
            }
        }
        
        public func send(message messageDict: [String : Any],
                         responseHandler: @escaping ResponseHandler) {
            do {
                guard let connection = self.connection else { throw POSIXError(.EINVAL) }
                
                self.connectionError = nil
                
                if !self.isValid {
                    throw CSASError.connectionInvalid
                }
            
                let message = xpc_dictionary_create(nil, nil, 0)
                message[kCSASRequestKey] = messageDict
                
                xpc_connection_send_message_with_reply(connection, message, DispatchQueue.main) {
                    do {
                        if let error = self.connectionError { throw error }
                        
                        let (response: response, fileHandles: fileHandles) = try CSASRequestSender.handleXPCReply($0)
                        
                        responseHandler(.success((response: response, fileHandles: fileHandles, persistentConnection: nil)))
                    } catch {
                        responseHandler(.error(error))
                    }
                }
            } catch {
                responseHandler(.error(error))
            }
        }
        
        private let closeQueue = DispatchQueue(label: "com.charlessoft.CSAuthSample.CSASRequestSender.PersistentConnection.closeQueue")
        public func close() {
            self.closeQueue.sync {
                if let connection = self.connection {
                    // Set a blank event handler to prevent it from getting called
                    // while we are closing the connection.
                    // Specifically, cancelling the connection will cause the
                    // XPC_ERROR_CONNECTION_INVALID event, which then causes
                    // this method to be called again.
                    xpc_connection_set_event_handler(connection) { _ in }
                    xpc_connection_cancel(connection)
                    self.connection = nil
                    
                    DispatchQueue.main.async { self.isValid = false }
                }
            }
        }
    }
    
    public typealias ResponseHandler = (Result<(response: [String : Any], fileHandles: [FileHandle], persistentConnection: PersistentConnection?)>) -> ()

    public var operationQueue = OperationQueue()

    private var helperID: String
    
    private var commandSet: [String : [String : Any]]
    
    private var authRef: AuthorizationRef?

    public init(commandSet: [String : [String : Any]], helperID: String) throws {
        var _authRef: AuthorizationRef?
        let err = AuthorizationCreate(nil, nil, [], &_authRef)
        
        if err != errSecSuccess { throw CSASRequestSender.convertOSStatus(err) }
        self.authRef = _authRef
        
        if commandSet.isEmpty {
            // there must be at least one command
            throw POSIXError(.EINVAL)
        }
        
        self.commandSet = commandSet
        self.helperID = helperID
    }
    
    deinit {
        self.cleanUp()
    }
    
    /// Make sure this is called before your application exits.
    public func cleanUp() {
        if let authRef = self.authRef {
            // destroy rights for a little added security
            AuthorizationFree(authRef, .destroyRights)
            self.authRef = nil
        }
    }
    
    public func blessHelperTool() throws {
        guard let authRef = self.authRef else { throw POSIXError(.EINVAL) }
        
        try kSMRightBlessPrivilegedHelper.withCString {
            var authItem = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)
            
            var authRights = AuthorizationRights(count: 1, items: &authItem)
            
            let flags: AuthorizationFlags = [.interactionAllowed, .preAuthorize, .extendRights]
            
            /* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
            let status = AuthorizationCopyRights(authRef, &authRights, nil, flags, nil)
            
            if status != errAuthorizationSuccess {
                throw CSASRequestSender.convertOSStatus(status)
            }
        }
        
        _ = try? self.syncRemoveHelperTool()
            
        /* This does all the work of verifying the helper tool against the application
         * and vice-versa. Once verification has passed, the embedded launchd.plist
         * is extracted and placed in /Library/LaunchDaemons and then loaded. The
         * executable is placed in /Library/PrivilegedHelperTools.
         */
        
        var smError: Unmanaged<CFError>? = nil
        if !SMJobBless(kSMDomainSystemLaunchd, self.helperID as CFString, self.authRef, &smError) {
            throw CSASRequestSender.convertCFError(smError?.takeRetainedValue())
        }
    }
    
    public func removeHelperTool(_ handler: @escaping (Error?) -> ()) {
        self.executeCommandInHelperTool(name: kCSASRemoveHelperCommand) {
            var smError: Unmanaged<CFError>? = nil
            if !SMJobRemove(kSMDomainSystemLaunchd, self.helperID as CFString, self.authRef, true, &smError) {
                handler(CSASRequestSender.convertCFError(smError?.takeRetainedValue()))
            } else if case let .error(error) = $0 {
                handler(error)
            } else {
                handler(nil)
            }
        }
    }
    
    private func syncRemoveHelperTool() throws {
        let semaphore = DispatchSemaphore(value: 0)
        var outError: Error? = nil
        
        self.removeHelperTool {
            outError = $0
            
            semaphore.signal()
        }
        
        semaphore.wait()
        
        if let error = outError { throw error }
    }
    
    public func requestHelperVersion(_ handler: @escaping (Result<String>) -> ()) {
        self.executeCommandInHelperTool(name: kCSASGetVersionCommand) {
            do {
                let (response: response, fileHandles: _, persistentConnection: _) = try $0.unwrap()
                
                guard let version = response[kCSASGetVersionResponse] as? String else {
                    throw CocoaError(.fileReadUnknown)
                }
                
                handler(.success(version))
            } catch {
                handler(.error(error))
            }
        }
    }
    
    public func executeCommandInHelperTool(name commandName: String,
                                           userInfo: [String : Any] = [:],
                                           responseHandler: @escaping ResponseHandler) {
        do {
            guard let authRef = self.authRef else { throw POSIXError(.EINVAL) }
            
            // Look up the command and preauthorize.  This has the nice side effect that
            // the authentication dialog comes up, in the typical case, here, rather than
            // in the helper tool.  This is good because the helper tool is global /and/
            // single threaded, so if it's waiting for an authentication dialog for user A
            // it can't handle requests from user B.
            
            guard let builtIn = CSASCreateBuiltInCommandSet().takeRetainedValue() as? [String : [String : Any]],
                let command = builtIn[commandName] ?? self.commandSet[commandName] else {
                throw POSIXError(.EINVAL)
            }
        
            if let rightName = command[kCSASCommandSpecRightNameKey as String] as? String {
                try rightName.withCString {
                    var item = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)
                    var rights = AuthorizationRights(count: 1, items: &item)
                    
                    let flags: AuthorizationFlags = [.extendRights, .interactionAllowed, .preAuthorize]
                    let status = AuthorizationCopyRights(authRef, &rights, nil, flags, nil)
                    
                    if status != errSecSuccess {
                        throw CSASRequestSender.convertOSStatus(status)
                    }
                }
            }
        
            // Open the XPC connection.
            
            var connectionError: Error? = nil
            let connection = xpc_connection_create_mach_service(self.helperID, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
            
            // Attempt to connect.
            
            xpc_connection_set_event_handler(connection) { event in
                switch xpc_get_type(event) {
                case XPC_TYPE_ERROR:
                    if connectionError == nil { connectionError = event.error }
                default:
                    if connectionError == nil { connectionError = CSASError.unexpectedEvent }
                }
            }
            
            xpc_connection_resume(connection)
            
            // Create an XPC dictionary object.
        
            let message = xpc_dictionary_create(nil, nil, 0)
        
            // Send the flattened AuthorizationRef to the tool.
        
            var extAuth = AuthorizationExternalForm()
            let authErr = AuthorizationMakeExternalForm(authRef, &extAuth)
        
            if authErr != errSecSuccess { throw CSASRequestSender.convertOSStatus(authErr) }
            
            xpc_dictionary_set_data(message, kCSASAuthorizationRefKey, &extAuth, MemoryLayout<AuthorizationExternalForm>.size)
        
            // Write the request.
        
            message[kCSASCommandKey] = commandName
        
            if !userInfo.isEmpty {
                message[kCSASRequestKey] = userInfo
            }
            
            // Send request.
            
            xpc_connection_send_message_with_reply(connection, message, nil) { reply in
                do {
                    if let error = connectionError { throw error }
                
                    let (response: response, fileHandles) = try CSASRequestSender.handleXPCReply(reply)
                                                                                    
                    let helperConnection: PersistentConnection? = {
                        if xpc_dictionary_get_bool(reply, kCSASCanAcceptFurtherInputKey) {
                            return PersistentConnection(xpcConnection: connection)
                        } else {
                            return nil
                        }
                    }()

                    self.operationQueue.addOperation {
                        responseHandler(.success((response: response, fileHandles: fileHandles, persistentConnection: helperConnection)))
                    }
                } catch {
                    self.operationQueue.addOperation { responseHandler(.error(error)) }
                }
            }
        } catch {
            // If something failed, let the user know.
            
            self.operationQueue.addOperation {
                responseHandler(.error(CSASRequestSender.convertError(error)))
            }
        }
    }
    
    private static func convertOSStatus(_ err: OSStatus) -> Error {
        return self.convertError(unsafeBitCast(CSASCreateCFErrorFromOSStatus(err, nil).takeRetainedValue(), to: NSError.self))
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

    private static func handleXPCReply(_ reply: xpc_object_t) throws -> (response: [String : Any], fileHandles: [FileHandle]) {
        guard let response = reply[kCSASRequestKey] as? [String : Any] else {
            // SR-7732: Casting to 'Error' results in a leak
            if let err = reply[kCSASErrorKey] as? NSError {
                throw self.convertError(err)
            } else {
                throw CocoaError(.fileReadUnknown)
            }
        }

        return (response: response, fileHandles: reply.fileHandles)
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

extension CSASError: CustomNSError {
    public static var errorDomain: String { return kCSASErrorDomain as String }
    public var errorCode: Int { return Int(self.rawValue) }
}
    
extension xpc_object_t {
    fileprivate var error: Error? {
        if xpc_get_type(self) == XPC_TYPE_ERROR {
            if self === XPC_ERROR_CONNECTION_INTERRUPTED {
                return CSASError.connectionInterrupted
            } else if self === XPC_ERROR_CONNECTION_INVALID {
                return CSASError.connectionInvalid
            } else {
                return CSASError.unexpectedConnection
            }
        } else {
            return nil
        }
    }
    
    fileprivate var fileHandles: [FileHandle] {
        guard let descriptors = xpc_dictionary_get_value(self, kCSASDescriptorArrayKey) else {
            return []
        }
        
        return (0..<xpc_array_get_count(descriptors)).compactMap {
            let fd = xpc_array_dup_fd(descriptors, $0)
            
            if fd < 0 { return nil }
            
            return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        }
    }
    
    fileprivate subscript(_ key: String) -> Any? {
        get {
            return CSASCreateCFTypeFromXPCMessage(xpc_dictionary_get_value(self, key))?.takeRetainedValue()
        }
        set {
            let xpcMessage = newValue.flatMap {
                sr7734_createXPC($0 as CFTypeRef).takeRetainedValue() as? xpc_object_t
            }
            
            xpc_dictionary_set_value(self, key, xpcMessage)
        }
    }
}

// Workaround for SR-7734
private let sr7734_createXPC: @convention(c) (Optional<AnyObject>) -> Unmanaged<AnyObject> = {
    let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CSASCreateXPCMessageFromCFType")!
    return unsafeBitCast(sym, to: (@convention(c) (Optional<AnyObject>) -> Unmanaged<AnyObject>).self)
}()
