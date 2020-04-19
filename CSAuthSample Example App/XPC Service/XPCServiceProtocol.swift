//
//  Example_App_XPC_ServiceProtocol.swift
//  Example App XPC Service
//
//  Created by Charles Srstka on 4/5/20.
//

import Foundation

@objc protocol XPCServiceProtocol {
    func sayHello(message: String, reply: @escaping (String?, Error?) -> ())
}
