//
//  XPCConvertible.swift
//  CSAuthSampleCommon
//
//  Created by Charles Srstka on 7/22/21.
//

import XPC

public protocol XPCConvertible {
    static func fromXPCObject(_ xpcObject: xpc_object_t) -> XPCConvertible?
    func toXPCObject() -> xpc_object_t?
}
