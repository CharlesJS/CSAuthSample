//
//  main.swift
//  CSAuthSample Example Helper Tool
//
//  Created by Charles Srstka on 4/5/20.
//

import Foundation
import CSAuthSampleHelper

let helperTool = HelperTool(
    helperID: Identifiers.helperID,
    commandSet: exampleCommandSet,
    senderRequirements: nil,
    connectionClass: HelperConnection.self,
    interface: NSXPCInterface(with: HelperToolProtocol.self)
)

helperTool.run()
