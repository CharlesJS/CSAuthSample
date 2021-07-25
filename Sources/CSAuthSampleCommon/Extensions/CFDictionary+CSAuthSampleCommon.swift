//
//  File.swift
//  File
//
//  Created by Charles Srstka on 7/22/21.
//

import CoreFoundation
import XPC

extension CFDictionary {
    public subscript(key: String) -> CFTypeRef? {
        self[CFString.fromString(key)]
    }

    public subscript(key: String, as typeID: CFTypeID) -> CFTypeRef? {
        self[CFString.fromString(key), as: typeID]
    }

    public subscript(key: CFTypeRef) -> CFTypeRef? {
        return CFDictionaryGetValue(self, unsafeBitCast(key, to: UnsafeRawPointer.self)) as CFTypeRef?
    }

    public subscript<T: CFTypeRef>(key: CFTypeRef, as typeID: CFTypeID) -> T? {
        guard let value = self[key], CFGetTypeID(value) == typeID else { return nil }

        return value as? T
    }

    public func readString(key: String) -> String? {
        self.readString(key: CFString.fromString(key))
    }

    public func readString(key: CFString) -> String? {
        let string: CFString? = self[key, as: CFStringGetTypeID()]

        return string?.toString()
    }
}

extension CFDictionary: XPCConvertible {
    private struct EncodingKeys {
        static let error = "com.charlessoft.CSAuthSample.CFDictionaryEncodingKeys.error"
        static let url = "com.charlessoft.CSAuthSample.CFDictionaryEncodingKeys.url"
    }

    public static func fromXPCObject(_ xpcObject: xpc_object_t) -> XPCConvertible? {
        let count = xpc_dictionary_get_count(xpcObject)

        if count == 1, let url = xpc_dictionary_get_value(xpcObject, EncodingKeys.url) {
            return CFURL.fromXPCObject(url)
        } else if count == 1, let err = xpc_dictionary_get_value(xpcObject, EncodingKeys.error) {
            return CFError.fromXPCObject(err)
        } else {
            var keyCallBacks = kCFTypeDictionaryKeyCallBacks
            var valueCallBacks = kCFTypeDictionaryValueCallBacks

            let dict = CFDictionaryCreateMutable(kCFAllocatorDefault, count, &keyCallBacks, &valueCallBacks)
            let utf8 = CFStringBuiltInEncodings.UTF8.rawValue

            xpc_dictionary_apply(xpcObject) {
                if let key = CFStringCreateWithCString(kCFAllocatorDefault, $0, utf8),
                   let value = $1.toCFType() {
                    CFDictionarySetValue(
                        dict,
                        unsafeBitCast(key as AnyObject, to: UnsafeRawPointer.self),
                        unsafeBitCast(value as AnyObject, to: UnsafeRawPointer.self)
                    )
                }

                return true
            }

            return dict
        }
    }

    public func toXPCObject() -> xpc_object_t? {
        let count = CFDictionaryGetCount(self)

        let keys = UnsafeMutablePointer<UnsafeRawPointer?>.allocate(capacity: count)
        defer { keys.deallocate() }

        let objs = UnsafeMutablePointer<UnsafeRawPointer?>.allocate(capacity: count)
        defer { objs.deallocate() }

        let xpcKeys = UnsafeMutablePointer<UnsafePointer<CChar>>.allocate(capacity: count)
        defer { xpcKeys.deallocate() }

        let xpcObjs = UnsafeMutablePointer<xpc_object_t?>.allocate(capacity: count)
        defer { xpcObjs.deallocate() }

        CFDictionaryGetKeysAndValues(self, keys, objs)

        let xpcCount = (0..<count).reduce(into: 0) { xpcCount, index in
            if let xpcConvertible = objs[index] as? XPCConvertible {
                unsafeBitCast(keys[index], to: CFString.self).withCString {
                    xpcKeys[xpcCount] = UnsafePointer(strdup($0))
                }

                switch CFGetTypeID(xpcConvertible as AnyObject) {
                case CFErrorGetTypeID():
                    let dict = xpc_dictionary_create_empty()
                    let xpcError = unsafeBitCast(xpcConvertible, to: CFError.self).toXPCObject()

                    xpc_dictionary_set_value(dict, EncodingKeys.error, xpcError)

                    xpcObjs[xpcCount] = dict
                case CFURLGetTypeID():
                    let dict = xpc_dictionary_create_empty()
                    let xpcURL = unsafeBitCast(xpcConvertible, to: CFURL.self).toXPCObject()

                    xpc_dictionary_set_value(dict, EncodingKeys.url, xpcURL)

                    xpcObjs[xpcCount] = dict
                default:
                    xpcObjs[xpcCount] = xpcConvertible.toXPCObject()
                }

                xpcCount += 1
            }
        }

        defer { (0..<xpcCount).forEach { free(UnsafeMutableRawPointer(mutating: xpcKeys[$0])) } }

        return xpc_dictionary_create(xpcKeys, xpcObjs, xpcCount)
    }
}
