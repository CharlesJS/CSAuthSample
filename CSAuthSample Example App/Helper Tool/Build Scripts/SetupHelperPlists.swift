//
//  SetupHelperPlists.swift
//  CSAuthSample Example Helper Tool
//
//  Created by Charles Srstka on 4/16/20.
//

// swiftlint:disable force_cast

import Foundation

let env = ProcessInfo.processInfo.environment

let helperID = env["HELPER_ID"]!
let xpcServiceID = env["XPC_SERVICE_ID"]!

let srcRoot = URL(fileURLWithPath: env["SRCROOT"]!)
let tempDir = URL(fileURLWithPath: env["TEMP_DIR"]!)

let infoSrcURL = srcRoot.appendingPathComponent("Helper Tool/Info.plist")
let launchdSrcURL = srcRoot.appendingPathComponent("Helper Tool/Launchd.plist")

let infoURL = tempDir.appendingPathComponent("Info.plist")
let launchdURL = tempDir.appendingPathComponent("Launchd.plist")

var info = NSDictionary(contentsOf: infoSrcURL) as! [String: Any]
var launchd = NSDictionary(contentsOf: launchdSrcURL) as! [String: Any]

info[kCFBundleVersionKey as String] = env["CURRENT_PROJECT_VERSION"]!
info[kCFBundleIdentifierKey as String] = helperID
info["SMAuthorizedClients"] = ["identifier \"\(xpcServiceID)\" and \(env["CS_REQUIREMENT"]!)"]

launchd["Label"] = helperID
launchd["MachServices"] = [helperID: true]

(info as NSDictionary).write(to: infoURL, atomically: true)
(launchd as NSDictionary).write(to: launchdURL, atomically: true)
