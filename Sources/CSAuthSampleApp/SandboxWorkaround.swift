//
//  SandboxWorkaround.swift
//  App Library
//
//  Created by Charles Srstka on 9/13/18.
//

import Cocoa

/**
 As of macOS 10.13, there is a UI issue that causes authentication boxes
 not to automatically gain focus when the app is sandboxed, which significantly
 impairs the user experience. This class provides an ugly workaround for this
 issue. Simply create an instance before beginning an operation that may possibly
 result in an authentication prompt, and stop it in the reply block.
 
 Usage example:
 ```
 let workaround = SandboxWorkaround()
 proxy.doSomePrivilegedOperation { reply in
     workaround.stop()
 
     ...
 }
 ```
*/
public class SandboxWorkaround {
    public init() {
        self.queue.async(execute: self.activateIfReady)
    }
    
    public func stop() {
        self.doneSemaphore.wait()
        defer { self.doneSemaphore.signal() }
        
        self.done = true
    }
    
    private let queue = DispatchQueue(label: "com.charlessoft.CSAuthSample.SandboxWorkaround.queue")
    private let doneSemaphore = DispatchSemaphore(value: 1)
    private var done: Bool = false
    
    private func activateIfReady() {
        let agentID = "com.apple.SecurityAgent"
        
        self.doneSemaphore.wait()
        defer { self.doneSemaphore.signal() }
        
        if self.done {
            return
        }
        
        if let securityAgent = NSRunningApplication.runningApplications(withBundleIdentifier: agentID).last {
            securityAgent.activate(options: [])
        } else {
            self.queue.asyncAfter(deadline: .now() + .microseconds(10),
                                  execute: self.activateIfReady)
        }
    }
}
