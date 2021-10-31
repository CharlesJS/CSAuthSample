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
    func handleBuiltInCommand(_ command: BuiltInCommands) throws -> [String : Any]? {
        switch command {
        case .getVersion:
            return try self.getVersion()
        case .uninstallHelperTool:
            try self.uninstallHelperTool()
            return [:]
        }
    }

    func getVersion() throws -> [String : Any] {
        if let version = self.version {
            return [kCFBundleVersionKey.toString() : version]
        } else {
            throw Errno.badFileTypeOrFormat
        }
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
