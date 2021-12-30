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

    /// Implementation of the `BuiltInCommands.getVersion` command.
    ///
    /// - Returns: The version of this helper tool.
    ///
    /// - Throws: `EBADF` if `CFBundleVersion` is missing from the helper tool’s embedded `Info.plist`.
    public func getVersion() throws -> String {
        if let version = self.version {
            return version
        } else {
            throw CFError.make(posixError: EBADF)
        }
    }

    /// Implementation of the `BuiltInCommands.uninstallHelperTool` command.
    ///
    /// - Throws: Any error that occurs in the process of uninstalling the helper tool.
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
