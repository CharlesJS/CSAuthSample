//
//  MessageSender.swift
//  Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleApp
import Foundation

class MessageSender {
    static let shared = MessageSender()

    private var _xpcConnection: NSXPCConnection?
    private var sema = DispatchSemaphore(value: 1)

    private var xpcConnection: NSXPCConnection {
        self.sema.wait()
        defer { self.sema.signal() }

        if let connection = self._xpcConnection {
            return connection
        }

        let connection = NSXPCConnection(serviceName: "com.charlessoft.CSAuthSample-Example.xpc")

        connection.remoteObjectInterface = NSXPCInterface(with: XPCServiceProtocol.self)

        connection.invalidationHandler = { [weak connection] in
            self.sema.wait()
            defer { self.sema.signal() }

            connection?.invalidationHandler = nil
            self._xpcConnection = nil
        }

        connection.resume()

        self._xpcConnection = connection
        return connection
    }

    func sayHello(reply: @escaping (Result<String, Error>) -> Void) {
        let proxy = self.getProxy { reply(.failure($0)) }
        let sandboxWorkaround = SandboxWorkaround()

        proxy.sayHello(message: "Hello there, helper tool!") {
            sandboxWorkaround.stop()

            if let replyMessage = $0 {
                reply(.success(replyMessage))
            } else {
                reply(.failure($1 ?? CocoaError(.fileReadUnknown)))
            }
        }
    }

    func getProxy(errorHandler: @escaping (Error) -> Void) -> XPCServiceProtocol {
        return self.xpcConnection.remoteObjectProxyWithErrorHandler(errorHandler) as! XPCServiceProtocol
    }
}
