//
//  CFError+CSAuthSampleCommon.swift
//  CSAuthSampleCommon
//
//  An extension to give CFError conformance to the Error protocol
//  without requiring your tool to link against Foundation.
//
//  Created by Charles Srstka on 7/20/21.
//

import CoreFoundation
import XPC

extension CFError: Error {
    public var _domain: String { CFErrorGetDomain(self).toString() }
    public var _code: Int { Int(CFErrorGetCode(self)) }
    public var _userInfo: AnyObject? { CFErrorCopyUserInfo(self) }
}

extension CFError: XPCConvertible {
    struct EncodingKeys {
        static let domain = "com.charlessoft.CSAuthSample.error.domain"
        static let code = "com.charlessoft.CSAuthSample.error.code"
        static let userInfo = "com.charlessoft.CSAuthSample.error.userInfo"
    }

    public static func fromXPCObject(_ xpcObject: xpc_object_t) -> XPCConvertible? {
        let domain = xpc_dictionary_get_value(xpcObject, EncodingKeys.domain)?.toCFType()
        let code = xpc_dictionary_get_int64(xpcObject, EncodingKeys.code)
        let userInfo = xpc_dictionary_get_value(xpcObject, EncodingKeys.userInfo)?.toCFType()

        return CFErrorCreate(
            kCFAllocatorDefault,
            unsafeBitCast(domain as AnyObject, to: CFString?.self),
            CFIndex(code),
            unsafeBitCast(userInfo as AnyObject, to: CFDictionary?.self)
        )
    }
}
