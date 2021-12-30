//
//  Errors.swift
//
//
//  Created by Charles Srstka on 10/31/21.
//

/// Errors specific to CSAuthSample.
public enum CSAuthSampleError: Error, Codable {
    /// The helper tool’s version did not match the version expected by the application.
    case versionMismatch(expected: String, actual: String)
}
