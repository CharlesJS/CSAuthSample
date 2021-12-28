//
//  Errors.swift
//  
//
//  Created by Charles Srstka on 10/31/21.
//

public enum CSAuthSampleError: Error, Codable {
    case versionMismatch(expected: String, actual: String)
}
