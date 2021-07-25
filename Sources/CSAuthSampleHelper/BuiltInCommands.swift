//
//  BuiltInCommands.swift
//  CSAuthSampleHelper
//
//  Created by Charles Srstka on 7/24/21.
//

import CSAuthSampleCommon
import CoreFoundation
import System

extension HelperTool {
    func handleBuiltInCommand(_ command: BuiltInCommands) throws -> CFDictionary? {
        switch command {
        case .getVersion:
            return try self.getVersion()
        case .uninstallHelperTool:
            try self.uninstallHelperTool()
            return nil
        }
    }

    func getVersion() throws -> CFDictionary {
        guard let version = CFDictionaryGetValue(
            self.infoPlist,
            unsafeBitCast(kCFBundleVersionKey, to: UnsafeRawPointer.self)
        ) else {
            throw Errno.badFileTypeOrFormat
        }

        var keyCallBacks = kCFTypeDictionaryKeyCallBacks
        var valueCallBacks = kCFTypeDictionaryValueCallBacks
        let dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 1, &keyCallBacks, &valueCallBacks)!

        CFDictionarySetValue(dict, unsafeBitCast(kCFBundleVersionKey, to: UnsafeMutableRawPointer.self), version)

        return dict
    }

    func uninstallHelperTool() throws {
        let servicePath = "/Library/LaunchDaemons/\(self.helperID).plist"

        if CFURLResourceIsReachable(self.url, nil) {
            try self.url.withUnsafeFileSystemRepresentation {
                guard unlink($0) == 0 else { throw Errno(rawValue: errno) }
            }
        }

        var s = stat()
        if lstat(servicePath, &s) == 0 {
            guard unlink(servicePath) == 0 else { throw Errno(rawValue: errno) }
        }
    }
}
