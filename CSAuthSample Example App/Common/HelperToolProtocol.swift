//
//  HelperToolProtocol.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import CSAuthSampleCommon
import Foundation

@objc protocol HelperToolProtocol: BuiltInCommands {
    func sayHello(authorizationData: Data, message: String, reply: @escaping (String?, Error?) -> Void)
}
