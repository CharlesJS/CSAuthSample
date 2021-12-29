//
//  GlobalSetupScript.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/12/20.
//

import Foundation

let env = ProcessInfo.processInfo.environment
let versionVarName = "CURRENT_PROJECT_VERSION"
let appID = env["PRODUCT_BUNDLE_IDENTIFIER"]!

let srcURL = URL(fileURLWithPath: env["SRCROOT"]!)
let derivedFileDir = URL(fileURLWithPath: env["DERIVED_FILE_DIR"]!)
let versionNumberURL = srcURL.appendingPathComponent("Common/Config/VersionNumber.xcconfig")
let requirementURL = srcURL.appendingPathComponent("Common/Config/CodeSignatureRequirement.xcconfig")

let version = Int(env[versionVarName]!)!

if !((try? derivedFileDir.checkResourceIsReachable()) ?? false) {
    try! FileManager.default.createDirectory(at: derivedFileDir, withIntermediateDirectories: true, attributes: nil)
}

let newVersion = "\(versionVarName) = \(version + 1)\n"

try! newVersion.write(to: versionNumberURL, atomically: true, encoding: .utf8)

let requirementConfig = "CS_REQUIREMENT = \(getRequirement())\n"

try! requirementConfig.write(to: requirementURL, atomically: true, encoding: .utf8)

func getRequirement() -> String {
    // Is there any way to generate the designated requirement string without invoking the codesign tool?
    // This is a bit of a kludge, but it's the only way I've been find to do this so far other than hard-coding the
    // format that `codesign` uses

    let tempFileName = UUID().uuidString
    let tempFileURL = derivedFileDir.appendingPathComponent(tempFileName)

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
