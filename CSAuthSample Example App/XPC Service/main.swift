//
//  main.swift
//  Example App XPC Service
//
//  Created by Charles Srstka on 4/5/20.
//

import Foundation

// Create the delegate for the service.
let delegate = ServiceDelegate()

// Set up the one NSXPCListener for this service. It will handle all incoming connections.
let listener = NSXPCListener.service()
listener.delegate = delegate

// Resuming the serviceListener starts this service. This method does not return.
listener.resume()
