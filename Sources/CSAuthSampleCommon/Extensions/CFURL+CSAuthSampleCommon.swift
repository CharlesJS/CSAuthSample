//
//  CFURL+CSAuthSampleCommon.swift
//  CSAuthSampleCommon
//
//  Created by Charles Srstka on 7/22/21.
//

import CoreFoundation
import XPC

extension CFURL: XPCConvertible {
    public static func fromXPCObject(_ xpcObject: xpc_object_t) -> XPCConvertible? {
        guard let string = unsafeBitCast(CFString.fromXPCObject(xpcObject), to: CFString?.self) else { return nil }

        return CFURLCreateWithString(kCFAllocatorDefault, string, nil)
    }

    public func toXPCObject() -> xpc_object_t? {
        return CFURLGetString(self).toXPCObject()
    }
}

extension CFURL {
    public func withUnsafeFileSystemRepresentation<T>(closure: (UnsafePointer<CChar>) throws -> T) rethrows -> T {
        let bufferSize = Int(PATH_MAX) + 1

        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        CFURLGetFileSystemRepresentation(self, true, buffer, bufferSize)

        return try buffer.withMemoryRebound(to: CChar.self, capacity: bufferSize) { try closure($0) }
    }
}
