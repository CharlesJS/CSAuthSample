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
    internal func setUpBuiltInHandlers() {
        self.setHandler(command: BuiltInCommands.getVersion, handler: self.getVersion)
        self.setHandler(command: BuiltInCommands.uninstallHelperTool, handler: self.uninstallHelperTool)
    }

    public func getVersion() throws -> String {
        if let version = self.version {
            return version
        } else {
            throw CFError.make(posixError: EBADF)
        }
    }

    public func uninstallHelperTool() throws {
        let servicePath = "/Library/LaunchDaemons/\(self.helperID).plist"

        if CFURLResourceIsReachable(self.url, nil) {
            try self.url.withUnsafeFileSystemRepresentation {
                guard unlink($0) == 0 else { throw CFError.make(posixError: errno) }
            }
        }

        var s = stat()
        if lstat(servicePath, &s) == 0 {
            guard unlink(servicePath) == 0 else { throw CFError.make(posixError: errno) }
        }
    }
}
