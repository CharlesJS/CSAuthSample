//
//  XPCService.swift
//  Example App XPC Service
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleApp
import Foundation

// This object implements the protocol which we have defined. It provides the actual behavior for the service.
// It is 'exported' by the service to make it available to the process hosting the service over an NSXPCConnection.
class XPCService: NSObject, XPCServiceProtocol {
    private static let bundle = Bundle(for: XPCService.self)
    private static let bundleVersion = XPCService.bundle.infoDictionary![kCFBundleVersionKey as String] as! String

    private let helperClient = try! HelperClient(
        helperID: "com.charlessoft.CSAuthSample-Example.helper",
        commandType: ExampleCommands.self,
        bundle: .main,
        tableName: "Prompts"
    )

    func sayHello(message: String, reply: @escaping (String?, Error?) -> Void) {
        Task {
            do {
                let response = try await self.helperClient.executeInHelperTool(command: ExampleCommands.sayHello, request: ["Message" : "Hi Zere"])
                reply(response["Message"] as? String ?? "(no response)", nil)
            } catch {
                reply(nil, error)
            }
        }
    }
}
