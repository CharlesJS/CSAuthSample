//
//  File.swift
//
//
//  Created by Charles Srstka on 12/28/21.
//

import CSAuthSampleCommon
import SwiftyXPC

// swift-format-ignore: AllPublicDeclarationsHaveDocumentation
public func csAuthSampleGlobalInit() {
    XPCErrorRegistry.shared.registerDomain(forErrorType: CSAuthSampleError.self)
}
