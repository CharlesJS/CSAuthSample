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
import os

open class HelperTool<CommandType: Command> {
    public let helperID: String
    public let url: CFURL
    public let infoPlist: CFDictionary
    public let timeoutInterval: CFTimeInterval?

    private let logger: Logger

    public init(commandType _: CommandType.Type, helperID: String? = nil, timeoutInterval: CFTimeInterval? = nil) {
        let path = CFString.fromString(CommandLine.arguments.first!)

        self.url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, .cfurlposixPathStyle, false)
        self.infoPlist = CFBundleCopyInfoDictionaryForURL(self.url)

        self.helperID = helperID ?? self.infoPlist.readString(key: kCFBundleIdentifierKey) ?? {
            fatalError("Helper ID must be specified, either in code or via \(kCFBundleIdentifierKey!) in Info.plist")
        }()

        self.timeoutInterval = timeoutInterval

        self.logger = Logger(subsystem: self.helperID, category: "com.charlessoft.CSAuthSample.HelperTool")
    }

    open func handleCommand(
        command: CommandType,
        request: CFDictionary?,
        authorization: AuthorizationRef,
        connection: xpc_connection_t
    ) async throws -> CFDictionary? {
        fatalError("Must override handleCommand(command:request:authorization:connection:)!")
    }

    public func run() -> Never {
        let helperID = self.helperID
        let service = xpc_connection_create_mach_service(helperID, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))

        xpc_connection_set_event_handler(service) { connection in
            xpc_connection_set_event_handler(connection) { self.handleEvent(connection: connection, event: $0) }
            xpc_connection_resume(connection)
        }

        xpc_connection_resume(service)

        dispatchMain()
    }

    private func handleEvent(connection: xpc_object_t, event: xpc_object_t) {
        switch xpc_get_type(event) {
        case XPC_TYPE_ERROR:
            self.handleError(connection: connection, event: event)
        case XPC_TYPE_DICTIONARY:
            Task {
                await self.handleRequest(event: event)
            }
        default:
            let description = xpc_copy_description(event)
            defer { free(description) }

            self.logger.notice("Unhandled XPC event: \(String(cString: description))")
        }
    }

    private func sendResponse(response: xpc_object_t, event: xpc_object_t) {
        if let reply = xpc_dictionary_create_reply(event) {
            xpc_dictionary_set_value(reply, DictionaryKeys.response, reply)
        }
    }

    private func handleError(connection: xpc_object_t, event: xpc_object_t) {
        if event === XPC_ERROR_CONNECTION_INVALID {
            // The client process on the other end of the connection has either
            // crashed or cancelled the connection. After receiving this error,
            // the connection is in an invalid state, and you do not need to
            // call xpc_connection_cancel(). Just tear down any associated state
            // here.

            if let ctx = xpc_connection_get_context(connection) {
                ctx.deallocate()
                xpc_connection_set_context(connection, nil)
            }
        } else if event === XPC_ERROR_TERMINATION_IMMINENT {
            self.logger.notice("Termination imminent")
        } else {
            self.logger.notice("Something went wrong")
        }
    }

    private func handleRequest(event: xpc_object_t) async {
        guard let remote = xpc_dictionary_get_remote_connection(event) else {
            self.logger.error("Couldn't establish connection to main application!")
            return
        }


        do {
            if let response = try await self.getResponse(connection: remote, event: event)?.toXPCObject() {
                self.sendResponse(response: response, event: event)
            }
        } catch {
            guard let error = error.toXPCObject() else {
                self.logger.error("Couldn't convert error object \(String(describing: error))")
                return
            }

            self.sendResponse(response: error, event: event)
        }
    }

    private func getResponse(connection: xpc_object_t, event: xpc_object_t) async throws -> CFDictionary? {
        guard let commandName = xpc_dictionary_get_string(event, DictionaryKeys.commandName),
              let command = CommandType[String(cString: commandName)] else {
            throw Errno.invalidArgument
        }

        try checkCallerCredentials(command: command, connection: connection)

        var authFormDataLength = 0
        guard let authFormExtData = xpc_dictionary_get_data(event, DictionaryKeys.authData, &authFormDataLength),
              authFormDataLength == MemoryLayout<AuthorizationExternalForm>.size else { throw Errno.invalidArgument }

        var authorization: AuthorizationRef? = nil
        let err = AuthorizationCreateFromExternalForm(
            authFormExtData.bindMemory(to: AuthorizationExternalForm.self, capacity: 1),
            &authorization
        )

        guard err == errAuthorizationSuccess, let authorization = authorization else { throw convertOSStatusError(err) }

        let request = xpc_dictionary_get_value(event, DictionaryKeys.request)?.toCFType().flatMap {
            CFGetTypeID($0 as AnyObject) == CFDictionaryGetTypeID() ? unsafeBitCast($0, to: CFDictionary.self) : nil
        }

        try self.checkAuthorization(command: command, authorization: authorization)

        if let command = command as? BuiltInCommands {
            return try self.handleBuiltInCommand(command)
        } else if let command = command as? CommandType {
            return try await handleCommand(
                command: command,
                request: request,
                authorization: authorization,
                connection: connection
            )
        } else {
            throw Errno.invalidArgument
        }
    }

    private func checkCallerCredentials(command: Command, connection: xpc_connection_t) throws {
        var pid = CFIndex(xpc_connection_get_pid(connection))
        var pidAttr = CFNumberCreate(kCFAllocatorDefault, .cfIndexType, &pid)
        var pidAttrKey = kSecGuestAttributePid

        var keyCallBacks = kCFTypeDictionaryKeyCallBacks
        var valueCallBacks = kCFTypeDictionaryValueCallBacks

        let codeAttrs = withUnsafeMutablePointer(to: &pidAttrKey) {
            $0.withMemoryRebound(to: UnsafeRawPointer?.self, capacity: 1) { keyPtr in
                withUnsafeMutablePointer(to: &pidAttr) {
                    $0.withMemoryRebound(to: UnsafeRawPointer?.self, capacity: 1) { keyAttrPtr in
                        CFDictionaryCreate(kCFAllocatorDefault, keyPtr, keyAttrPtr, 1, &keyCallBacks, &valueCallBacks)
                    }
                }
            }
        }

        var code: SecCode? = nil
        var err = SecCodeCopyGuestWithAttributes(nil, codeAttrs, [], &code)
        guard err == errSecSuccess, let code = code else { throw convertOSStatusError(err) }

        var requirement: SecRequirement? = nil

        if let requirementString = command.codeSigningRequirement {
            err = SecRequirementCreateWithString(CFString.fromString(requirementString), [], &requirement)
            guard err == errSecSuccess, requirement != nil else { throw convertOSStatusError(err) }
        }

        err = SecCodeCheckValidity(code, [], requirement)
        guard err == errSecSuccess else { throw convertOSStatusError(err) }
    }

    private func checkAuthorization(command: Command, authorization auth: AuthorizationRef) throws {
        // Acquire the associated right for the command.
        try command.name.withCString {
            var item = AuthorizationItem(name: $0, valueLength: 0, value: nil, flags: 0)

            try withUnsafeMutablePointer(to: &item) {
                var rights = AuthorizationRights(count: 1, items: $0)

                let err = AuthorizationCopyRights(auth, &rights, nil, [.extendRights, .interactionAllowed], nil)

                if err != errAuthorizationSuccess {
                    throw convertOSStatusError(err)
                }
            }
        }
    }

}
