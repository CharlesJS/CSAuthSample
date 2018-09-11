//
//  Common.swift
//  App Library (C Helper)
//
//  Created by Charles Srstka on 7/1/18.
//

import Foundation

public enum Result<T> {
    case success(T)
    case error(Error)
    
    public func unwrap() throws -> T {
        switch self {
        case let .success(ret):
            return ret
        case let .error(error):
            throw error
        }
    }
}
