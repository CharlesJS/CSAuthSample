//
//  GlobalSetupScript.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/12/20.
//

// swiftlint:disable force_try

import Foundation

let env = ProcessInfo.processInfo.environment
let versionVarName = "CURRENT_PROJECT_VERSION"

let srcURL = URL(fileURLWithPath: env["SRCROOT"]!)
let tempDir = URL(fileURLWithPath: env["TEMP_DIR"]!)
let configURL = srcURL.appendingPathComponent("Common/Config/CSAuthSample-Example.xcconfig")

let version = Int(env[versionVarName]!)!

let newConfig = """
\(versionVarName) = \(version + 1)
APP_BUNDLE_ID = \(Identifiers.appID)
XPC_SERVICE_ID = \(Identifiers.xpcServiceID)
HELPER_ID = \(Identifiers.helperID)
CS_REQUIREMENT=\(getRequirement())
"""

try! newConfig.write(to: configURL, atomically: true, encoding: .utf8)

func getRequirement() -> String {
    // TODO: Is there any way to generate the designated requirement string without invoking the codesign tool?
    // This is a bit of a kludge, but it's the only way I've been find to do this so far other than hard-coding the
    // format that `codesign` uses

    let tempFileName = UUID().uuidString
    let tempFileURL = tempDir.appendingPathComponent(tempFileName)

    try! Data().write(to: tempFileURL)
    defer { try! FileManager.default.removeItem(at: tempFileURL) }

    let codesign = Process()
    codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    codesign.arguments = ["-s", env["CODE_SIGN_IDENTITY"]!, "-i", "", tempFileURL.path]
    try! codesign.run()
    codesign.waitUntilExit()

    var code: SecStaticCode?
    assert(SecStaticCodeCreateWithPath(tempFileURL as CFURL, [], &code) == errSecSuccess)

    var requirement: SecRequirement?
    assert(SecCodeCopyDesignatedRequirement(code!, [], &requirement) == errSecSuccess)

    var cfRequirementString: CFString?
    assert(SecRequirementCopyString(requirement!, [], &cfRequirementString) == errSecSuccess)

    var requirementString = cfRequirementString! as String

    let identifierRange = requirementString.range(of: "identifier \"\(tempFileName)\" and ")!
    requirementString.replaceSubrange(identifierRange, with: "")

    return requirementString
}
