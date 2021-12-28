//
//  CommandValidation.swift
//  
//
//  Created by Charles Srstka on 12/26/21.
//

import CSAuthSampleCommon
import CSCoreFoundation
import CoreFoundation
import SwiftyXPC
import System

public func validateArguments(command: CommandSpec, requestType: Codable.Type, responseType: Codable.Type) throws {
    if requestType != (command.requestType ?? XPCNull.self) {
        throw CFError.make(posixError: EINVAL)
    }

    switch command.responseType {
    case .noWait:
        if responseType != XPCNull.self {
            throw CFError.make(posixError: EINVAL)
        }
    case .wait(let type):
        if responseType != (type ?? XPCNull.self) {
            throw CFError.make(posixError: EINVAL)
        }
    }
}
