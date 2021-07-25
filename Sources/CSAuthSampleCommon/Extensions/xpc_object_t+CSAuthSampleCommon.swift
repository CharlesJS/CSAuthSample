//
//  xpc_object_t+CSAuthSampleCommon.swift
//  CSAuthSampleCommon
//
//  Created by Charles Srstka on 7/22/21.
//

import CoreFoundation
import System
import XPC

extension xpc_object_t {
    public func toCFType() -> XPCConvertible? {
        switch xpc_get_type(self) {
        case XPC_TYPE_NULL:
            return CFNull.fromXPCObject(self)
        case XPC_TYPE_BOOL:
            return CFBoolean.fromXPCObject(self)
        case XPC_TYPE_INT64, XPC_TYPE_UINT64, XPC_TYPE_DOUBLE:
            return CFNumber.fromXPCObject(self)
        case XPC_TYPE_DATE:
            return CFDate.fromXPCObject(self)
        case XPC_TYPE_DATA:
            return CFData.fromXPCObject(self)
        case XPC_TYPE_ENDPOINT:
            return XPCEndpoint(connection: self)
        case XPC_TYPE_FD:
            return FileDescriptorWrapper.fromXPCObject(self)
        case XPC_TYPE_STRING:
            return CFString.fromXPCObject(self)
        case XPC_TYPE_UUID:
            return CFUUID.fromXPCObject(self)
        case XPC_TYPE_ARRAY:
            return CFArray.fromXPCObject(self)
        case XPC_TYPE_DICTIONARY:
            return CFDictionary.fromXPCObject(self)
        default:
            return nil
        }
    }

    public static func fromCFType(_ obj: XPCConvertible) -> xpc_object_t? {
        if let endpoint = obj as? XPCEndpoint {
            return endpoint.toXPCObject()
        } else if let fd = obj as? FileDescriptorWrapper {
            return fd.toXPCObject()
        } else {
            switch CFGetTypeID(obj as AnyObject) {
            case CFNullGetTypeID():
                return unsafeBitCast(obj, to: CFNull.self).toXPCObject()
            case CFBooleanGetTypeID():
                return unsafeBitCast(obj, to: CFBoolean.self).toXPCObject()
            case CFNumberGetTypeID():
                return unsafeBitCast(obj, to: CFNumber.self).toXPCObject()
            case CFDateGetTypeID():
                return unsafeBitCast(obj, to: CFDate.self).toXPCObject()
            case CFDataGetTypeID():
                return unsafeBitCast(obj, to: CFData.self).toXPCObject()
            case CFStringGetTypeID():
                return unsafeBitCast(obj, to: CFString.self).toXPCObject()
            case CFUUIDGetTypeID():
                return unsafeBitCast(obj, to: CFUUID.self).toXPCObject()
            case CFArrayGetTypeID():
                return unsafeBitCast(obj, to: CFArray.self).toXPCObject()
            case CFDictionaryGetTypeID():
                return unsafeBitCast(obj, to: CFDictionary.self).toXPCObject()
            case CFURLGetTypeID():
                return unsafeBitCast(obj, to: CFURL.self).toXPCObject()
            case CFErrorGetTypeID():
                return unsafeBitCast(obj, to: CFError.self).toXPCObject()
            default:
                return nil
            }
        }
    }
}
