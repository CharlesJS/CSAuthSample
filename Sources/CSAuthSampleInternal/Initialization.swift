//
//  File.swift
//  
//
//  Created by Charles Srstka on 12/28/21.
//

import SwiftyXPC
import CSAuthSampleCommon

public func csAuthSampleGlobalInit() {
    XPCErrorRegistry.shared.registerDomain(forErrorType: CSAuthSampleError.self)
}
