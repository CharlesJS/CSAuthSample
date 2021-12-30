//
//  CommandSpec Internal.swift
//  
//
//  Created by Charles Srstka on 12/30/21.
//

import CSAuthSampleCommon
import Security.AuthorizationDB

// swift-format-ignore: AllPublicDeclarationsHaveDocumentation
extension CommandSpec {
    public static func setUpAccessRights(
        commandSet: [CommandSpec],
        authorization: AuthorizationRef,
        bundle: CFBundle?,
        tableName: String?
    ) throws {
        for eachCommand in BuiltInCommands.all + commandSet {
            // First get the right.  If we get back errAuthorizationDenied that means there's
            // no current definition, so we add our default one.

            var err = AuthorizationRightGet(eachCommand.name, nil)

            if err == errAuthorizationDenied {
                err = AuthorizationRightSet(
                    authorization,
                    eachCommand.name,
                    CFString.fromString(eachCommand.rule),
                    eachCommand.prompt.map { CFString.fromString($0) },
                    bundle,
                    tableName.map { CFString.fromString($0) }
                )

                guard err == errAuthorizationSuccess else {
                    throw CFError.make(osStatus: err)
                }
            } else {
                // A right already exists (err == noErr) or any other error occurs, we
                // assume that it has been set up in advance by the system administrator or
                // this is the second time we've run.  Either way, there's nothing more for
                // us to do.
            }
        }
    }
}

extension BuiltInCommands {
    // swift-format-ignore: AllPublicDeclarationsHaveDocumentation
    public static let all: [CommandSpec] = [Self.getVersion, Self.uninstallHelperTool]
}
