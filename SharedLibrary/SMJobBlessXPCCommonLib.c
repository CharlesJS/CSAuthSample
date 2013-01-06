#include <sys/ucred.h>

/*
 File:       BetterAuthorizationSampleLib.c
 
 Contains:   Implementation of reusable code for privileged helper tools.
 
 Written by: DTS
 
 Modified by Charles Srstka, 2013.
 
 Copyright:  Copyright (c) 2007 Apple Inc. All Rights Reserved.
 
 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple, Inc.
 ("Apple") in consideration of your agreement to the following terms, and your
 use, installation, modification or redistribution of this Apple software
 constitutes acceptance of these terms.  If you do not agree with these terms,
 please do not use, install, modify or redistribute this Apple software.
 
 In consideration of your agreement to abide by the following terms, and subject
 to these terms, Apple grants you a personal, non-exclusive license, under Apple's
 copyrights in this original Apple software (the "Apple Software"), to use,
 reproduce, modify and redistribute the Apple Software, with or without
 modifications, in source and/or binary forms; provided that if you redistribute
 the Apple Software in its entirety and without modifications, you must retain
 this notice and the following text and disclaimers in all such redistributions of
 the Apple Software.  Neither the name, trademarks, service marks or logos of
 Apple, Inc. may be used to endorse or promote products derived from the
 Apple Software without specific prior written permission from Apple.  Except as
 expressly stated in this notice, no other rights or licenses, express or implied,
 are granted by Apple herein, including but not limited to any patent rights that
 may be infringed by your derivative works or by other works in which the Apple
 Software may be incorporated.
 
 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 COMBINATION WITH YOUR PRODUCTS.
 
 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
 OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
 (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 */

#include "SMJobBlessXPCCommonLib.h"

// At runtime SJBX only requires CoreFoundation.  However, at build time we need
// CoreServices for the various OSStatus error codes in "MacErrors.h".  Thus, by default,
// we include CoreServices at build time.  However, you can flip this switch to check
// that you're not accidentally using any other CoreServices things.

#if 1
#include <CoreServices/CoreServices.h>
#else
#warning Do not ship this way!
#include <CoreFoundation/CoreFoundation.h>
#include "/System/Library/Frameworks/CoreServices.framework/Frameworks/CarbonCore.framework/Headers/MacErrors.h"
#endif

//////////////////////////////////////////////////////////////////////////////////
#pragma mark ***** Constants

// kSJBXMaxNumberOfKBytes has two uses:
//
// 1. When receiving a dictionary, it is used to limit the size of the incoming
//    data.  This ensures that a non-privileged client can't exhaust the
//    address space of a privileged helper tool.
//
// 2. Because it's less than 4 GB, this limit ensures that the dictionary size
//    can be sent as an architecture-neutral uint32_t.

#define kSJBXMaxNumberOfKBytes			(1024 * 1024)

CFStringRef const kSJBXErrorDomainAuthorization = CFSTR("kSJBXDomainAuthorization");

/////////////////////////////////////////////////////////////////
#pragma mark ***** Common Code

static Boolean SJBXIsBinaryPropertyListData(const void * plistBuffer, size_t plistSize)
// Make sure that whatever is passed into the buffer that will
// eventually become a plist (and then sequentially a dictionary)
// is NOT in binary format.
{
    static const char kSJBXBinaryPlistWatermark[6] = "bplist";
    
    assert(plistBuffer != NULL);
	
	return (plistSize >= sizeof(kSJBXBinaryPlistWatermark))
    && (memcmp(plistBuffer, kSJBXBinaryPlistWatermark, sizeof(kSJBXBinaryPlistWatermark)) == 0);
}

static bool SJBXOSStatusToErrno(OSStatus errNum, int *posixErr)
{
    bool converted = true;
    
    switch (errNum) {
		case noErr:
			*posixErr = 0;
			break;
        case memFullErr:
            *posixErr = ENOMEM;
            break;
		case kEOPNOTSUPPErr:
			*posixErr = ENOTSUP;
			break;
        case kECANCELErr:
        case userCanceledErr:
            *posixErr = ECANCELED;             // note spelling difference
            break;
        default:
            if ( (errNum >= errSecErrnoBase) && (errNum <= (errSecErrnoBase + ELAST)) ) {
                *posixErr = (int) errNum - errSecErrnoBase;	// POSIX based error
            } else {
				converted = false;
			}
    }

    return converted;
}

extern CFErrorRef SJBXCreateCFErrorFromErrno(int errNum) {
    return CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainPOSIX, errNum, NULL);
}

extern CFErrorRef SJBXCreateCFErrorFromCarbonError(OSStatus err) {
    // Prefer POSIX errors over OSStatus ones if possible, as they tend to present nicer error messages to the end user.
    
    int posixErr;
    
    if (SJBXOSStatusToErrno(err, &posixErr)) {
        return SJBXCreateCFErrorFromErrno(posixErr);
    } else {
        return CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainOSStatus, err, NULL);
    }
}

extern CFErrorRef SJBXCreateCFErrorFromSecurityError(OSStatus err) {
    if (err == errAuthorizationCanceled) {
        return SJBXCreateCFErrorFromErrno(ECANCELED);
    } else if (err >= errSecErrnoBase && err <= errSecErrnoLimit) {
        return SJBXCreateCFErrorFromErrno(err - errSecErrnoBase);
    } else {
        CFStringRef errStr = SecCopyErrorMessageString(err, NULL);
        CFDictionaryRef userInfo = CFDictionaryCreate(kCFAllocatorDefault,
                                                      (const void **)&kCFErrorLocalizedFailureReasonKey,
                                                      (const void **)&errStr,
                                                      1,
                                                      &kCFTypeDictionaryKeyCallBacks,
                                                      &kCFTypeDictionaryValueCallBacks);
        
        CFErrorRef error = CFErrorCreate(kCFAllocatorDefault, kSJBXErrorDomainAuthorization, err, userInfo);
        
        CFRelease(userInfo);
        CFRelease(errStr);
        
        return error;
    }
}

extern CFErrorRef SJBXCreateErrorFromResponse(CFDictionaryRef response) {
    CFErrorRef error = NULL;
    CFDictionaryRef errorDict = NULL;
    
    if (response == NULL) {
        error = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
    } else {
        errorDict = CFDictionaryGetValue(response, CFSTR(kSJBXErrorKey));
    }
    
    if (errorDict != NULL) {
        CFStringRef domain = CFDictionaryGetValue(errorDict, CFSTR(kSJBXErrorDomainKey));
        CFIndex code = 0;
        CFNumberRef codeNum = CFDictionaryGetValue(errorDict, CFSTR(kSJBXErrorCodeKey));
        CFDictionaryRef userInfo = CFDictionaryGetValue(errorDict, CFSTR(kSJBXErrorUserInfoKey));
        
        if (!CFNumberGetValue(codeNum, kCFNumberCFIndexType, &code)) {
            code = -1;
        }
    
        error = CFErrorCreate(kCFAllocatorDefault, domain, code, userInfo);
    }
    
    return error;
}

extern bool SJBXReadDictionary(xpc_object_t xpcIn, CFDictionaryRef *dictPtr, CFErrorRef *errorPtr)
// Create a CFDictionary by reading the XML data from xpcIn.
// It first reads the data in, and then
// unflattens the data into a CFDictionary.
//
// On success, the caller is responsible for releasing *dictPtr.
//
// See also the companion routine, SJBXWriteDictionary, below.
{
    bool                success = true;
	size_t				dictSize;
	const void *		dictBuffer;
	CFDataRef			dictData;
	CFPropertyListRef 	dict;
    
    // Pre-conditions
    
	assert(xpcIn >= 0);
	assert( dictPtr != NULL);
	assert(*dictPtr == NULL);
	
	dictBuffer = NULL;
	dictData   = NULL;
	dict       = NULL;
    
	// Read the data and unflatten.
	
	if (success) {
        dictBuffer = xpc_dictionary_get_data(xpcIn, kSJBXRequestKey, &dictSize);
        
        if (dictBuffer == NULL) {
            success = false;
            if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
        }
	}
	if ( success && SJBXIsBinaryPropertyListData(dictBuffer, dictSize) ) {
        success = false;
        if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
	}
	if (success) {
		dictData = CFDataCreateWithBytesNoCopy(NULL, dictBuffer, dictSize, kCFAllocatorNull);
		if (dictData == NULL) {
            success = false;
            if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
		}
	}
	if (success) {
		dict = CFPropertyListCreateFromXMLData(NULL, dictData, kCFPropertyListImmutable, NULL);
		if (dict == NULL) {
            success = false;
            if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
		}
	}
	if ( success && (CFGetTypeID(dict) != CFDictionaryGetTypeID()) ) {
        success = false;
        if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromErrno(EINVAL); // only CFDictionaries need apply
	}
	// CFShow(dict);
	
	// Clean up.
	
	if (!success) {
		if (dict != NULL) {
			CFRelease(dict);
		}
		dict = NULL;
	}
	*dictPtr = (CFDictionaryRef) dict;

	if (dictData != NULL) {
		CFRelease(dictData);
	}
	
	assert( (success != false) == (*dictPtr != NULL) );
	
	return success;
}

extern bool SJBXWriteDictionary(CFDictionaryRef dict, xpc_object_t message, CFErrorRef *errorPtr)
// Write a dictionary to an XPC message by flattening
// it into XML.
//
// See also the companion routine, SJBXReadDictionary, above.
{
    bool                success = true;
	CFDataRef			dictData;
    
    // Pre-conditions
    
	assert(dict != NULL);
	assert(message >= 0);
	
	dictData   = NULL;
	
    // Get the dictionary as XML data.
    
	dictData = CFPropertyListCreateXMLData(NULL, dict);
	if (dictData == NULL) {
        success = false;
        if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
	}
    
    // Send the length, then send the data.  Always send the length as a big-endian
    // uint32_t, so that the app and the helper tool can be different architectures.
    //
    // The MoreAuthSample version of this code erroneously assumed that CFDataGetBytePtr
    // can fail and thus allocated an extra buffer to copy the data into.  In reality,
    // CFDataGetBytePtr can't fail, so this version of the code doesn't do the unnecessary
    // allocation.
    
    if ( success && (CFDataGetLength(dictData) > kSJBXMaxNumberOfKBytes) ) {
        success = false;
        if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromErrno(EINVAL);
    }
    
	if (success) {
        xpc_dictionary_set_data(message, kSJBXRequestKey, CFDataGetBytePtr(dictData), CFDataGetLength(dictData));
	}
    
	if (dictData != NULL) {
		CFRelease(dictData);
	}
    
	return success;
}

extern bool FindCommand(
                        CFDictionaryRef             request,
                        const SJBXCommandSpec		commands[],
                        size_t *                    commandIndexPtr,
                        CFErrorRef *                errorPtr
                        )
// FindCommand is a simple utility routine for checking that the
// command name within a request is valid (that is, matches one of the command
// names in the SJBXCommandSpec array).
//
// On success, *commandIndexPtr will be the index of the requested command
// in the commands array.  On error, the value in *commandIndexPtr is undefined.
{
	bool                        success = true;
    CFStringRef                 commandStr;
    char *                      command;
	UInt32						commandSize = 0;
	size_t						index = 0;
	
	// Pre-conditions
	
	assert(request != NULL);
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
	assert(commandIndexPtr != NULL);
    
    command = NULL;
    
    // Get the command as a C string.  To prevent untrusted command string from
	// trying to run us out of memory, we limit its length to 1024 UTF-16 values.
    
    commandStr = CFDictionaryGetValue(request, CFSTR(kSJBXCommandKey));
    if ( (commandStr == NULL) || (CFGetTypeID(commandStr) != CFStringGetTypeID()) ) {
        success = false;
        if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromErrno(EINVAL);
    }
	commandSize = CFStringGetLength(commandStr);
	if ( (success) && (commandSize > 1024) ) {
		success = false;
        if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromErrno(EINVAL);
	}
    if (success) {
        size_t      bufSize;
        
        bufSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(commandStr), kCFStringEncodingUTF8) + 1;
        command = malloc(bufSize);
        
        if (command == NULL) {
            success = false;
            if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromErrno(ENOMEM);
        } else if ( ! CFStringGetCString(commandStr, command, bufSize, kCFStringEncodingUTF8) ) {
            success = false;
            if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
        }
    }
    
    // Search the commands array for that command.
    
    if (success) {
        do {
            if ( strcmp(commands[index].commandName, command) == 0 ) {
                *commandIndexPtr = index;
                break;
            }
            index += 1;
            if (commands[index].commandName == NULL) {
                success = false;
                if (errorPtr != NULL) *errorPtr = SJBXCreateCFErrorFromErrno(ENOENT);
                break;
            }
        } while (true);
    }
    
    free(command);
    
	return success;
}
