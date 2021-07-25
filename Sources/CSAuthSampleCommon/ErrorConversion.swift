//
//  File.swift
//  File
//
//  Created by Charles Srstka on 7/15/21.
//

import System
import Security.SecBase
import CoreServices.CarbonCore.MacErrors
import CoreFoundation

public func convertOSStatusError(_ err: OSStatus) -> Error {
    switch Int(err) {
    case Int(errSecErrnoBase)...Int(errSecErrnoLimit):
        return Errno(rawValue: CInt(err) - errSecErrnoBase)
    case userCanceledErr, Int(errAuthorizationCanceled), Int(errSecCSCancelled), errAEWaitCanceled, kernelCanceledErr,
        kOTCanceledErr, kECANCELErr, errIACanceled, kRAConnectionCanceled, kTXNUserCanceledOperationErr,
        kFBCindexingCanceled, kFBCaccessCanceled, kFBCsummarizationCanceled:
        return Errno.canceled
    case fnfErr:
        return Errno.noSuchFileOrDirectory
    case fileBoundsErr, fsDataTooBigErr:
        return Errno.fileTooLarge
    case dupFNErr:
        return Errno.fileExists
    case dskFulErr, errFSNotEnoughSpaceForOperation:
        return Errno.noSpace
    case vLckdErr:
        return Errno.readOnlyFileSystem
    default:
        var keyCallBacks = kCFTypeDictionaryKeyCallBacks
        var valueCallBacks = kCFTypeDictionaryValueCallBacks

        let info = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &keyCallBacks, &valueCallBacks)

        if let msg = SecCopyErrorMessageString(err, nil) {
            CFDictionarySetValue(
                info,
                unsafeBitCast(kCFErrorLocalizedFailureReasonKey, to: UnsafeRawPointer.self),
                unsafeBitCast(msg, to: UnsafeRawPointer.self)
            )
        }

        return CFErrorCreate(kCFAllocatorDefault, CFString.fromString("NSOSStatusErrorDomain"), CFIndex(err), info)
    }
}

extension Error {
    public func toXPCObject() -> xpc_object_t? {
        let errorDict = xpc_dictionary_create_empty()

        self._domain.withCString { xpc_dictionary_set_string(errorDict, CFError.EncodingKeys.domain, $0) }
        xpc_dictionary_set_int64(errorDict, CFError.EncodingKeys.code, Int64(self._code))
        if let userInfo = unsafeBitCast(self._userInfo, to: CFDictionary?.self)?.toXPCObject() {
            xpc_dictionary_set_value(errorDict, CFError.EncodingKeys.userInfo, userInfo)
        }

        return errorDict
    }
}
