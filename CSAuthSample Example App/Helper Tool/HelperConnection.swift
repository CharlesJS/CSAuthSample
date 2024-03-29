//
//  HelperConnection.swift
//  Example Helper Tool
//
//  Created by Charles Srstka on 4/15/20.
//  Copyright © 2020-2021 Charles Srstka. All rights reserved.
//

import CSAuthSampleHelper
import Foundation

class HelperConnection: CSAuthSampleHelper.HelperConnection, HelperToolProtocol {
    func sayHello(authorizationData: Data, message: String, reply: @escaping (String?, Error?) -> ()) {
        if let error = self.checkAuthorization(authorizationData) {
            reply(nil, error)
            return
        }

        let replyMessage = """
            Received message from app: “\(message)”
            Sending reply to app: “Hello app! My UID is \(getuid()) and my GID is \(getgid())!
            """

        reply(replyMessage, nil)
    }
}
