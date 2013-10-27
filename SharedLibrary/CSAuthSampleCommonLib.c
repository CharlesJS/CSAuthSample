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

#include "CSAuthSampleCommonLib.h"

// At runtime CSAS only requires CoreFoundation.  However, at build time we need
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

// 10_6
extern const struct _xpc_type_s _xpc_type_array WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_bool WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_data WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_date WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_dictionary WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_double WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_error WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_int64 WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_null WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_string WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_uint64 WEAK_IMPORT_ATTRIBUTE;
extern const struct _xpc_type_s _xpc_type_uuid WEAK_IMPORT_ATTRIBUTE;

#include <syslog.h>

//////////////////////////////////////////////////////////////////////////////////
#pragma mark ***** Constants

CFStringRef const kCSASErrorDomain = CFSTR("kCSASErrorDomain");

// For encoding NSURLs and NSErrors in a manner that will allow them to be passed along the message port without complaints.

static const char * const kCSASEncodedURLKey = "kCSAuthSampleEncodedeURLKey";
static const char * const kCSASEncodedErrorKey = "kCSASEncodedErrorKey";

/////////////////////////////////////////////////////////////////
#pragma mark ***** Common Code

static CFMutableDictionaryRef CSASCreateErrorUserInfoForURL(CFURLRef url) {
    CFMutableDictionaryRef userInfo = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    if (url != NULL) {
        CFStringRef scheme = CFURLCopyScheme(url);
        
        CFDictionarySetValue(userInfo, kCFErrorURLKey, url);
        
        if (CFEqual(scheme, CFSTR("file"))) {
            CFStringRef path = CFURLCopyPath(url);
            
            CFDictionarySetValue(userInfo, kCFErrorFilePathKey, path);
            
            CFRelease(path);
        }
        
        CFRelease(scheme);
    }
    
    return userInfo;
}

extern CFErrorRef CSASCreateCFErrorFromErrno(int errNum, CFURLRef url) {
    CFDictionaryRef userInfo = CSASCreateErrorUserInfoForURL(url);
    
    CFErrorRef error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainPOSIX, errNum, userInfo);
    
    CFRelease(userInfo);
    
    return error;
}

extern CFErrorRef CSASCreateCFErrorFromOSStatus(OSStatus err, CFURLRef url) {
    // Prefer POSIX errors over OSStatus ones if possible, as they tend to present nicer error messages to the end user.
    
    if ((err >= errSecErrnoBase) && (err <= errSecErrnoLimit)) {
        return CSASCreateCFErrorFromErrno(err - errSecErrnoBase, url);
    } else {
        CFMutableDictionaryRef userInfo = CSASCreateErrorUserInfoForURL(url);
        CFStringRef errStr = SecCopyErrorMessageString(err, NULL);
        CFErrorRef error;
        
        if (errStr != NULL) {
            CFDictionarySetValue(userInfo, kCFErrorLocalizedFailureReasonKey, errStr);
            CFRelease(errStr);
        }
        
        error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainOSStatus, err, userInfo);
        
        CFRelease(userInfo);
        
        return error;
    }
}

extern char *CSASCreateFileSystemRepresentationForURL(CFURLRef url, CFErrorRef *error) {
    CFStringRef scheme = CFURLCopyScheme(url);
    bool isFile = CFEqual(scheme, CFSTR("file"));
    
    CFRelease(scheme);
    
    if (!isFile) {
        if (error) *error = CSASCreateCFErrorFromErrno(EINVAL, url);
        return NULL;
    } else {
        size_t bufsize = PATH_MAX + 1;
        uint8_t *buf = malloc(bufsize);
        
        while (!CFURLGetFileSystemRepresentation(url, true, buf, bufsize)) {
            free(buf);
            bufsize += 100;
            buf = malloc(bufsize);
        }
        
        return (char *)buf;
    }
}

extern char *CSASCreateFileSystemRepresentationForPath(CFStringRef path) {
    size_t bufsize = PATH_MAX + 1;
    char *buf = malloc(bufsize);
    
    while (!CFStringGetFileSystemRepresentation(path, buf, bufsize)) {
        free(buf);
        bufsize += 100;
        buf = malloc(bufsize);
    }
    
    return buf;
}

extern CFTypeRef CSASCreateCFTypeFromXPCMessage(xpc_object_t message) {
    xpc_type_t type;
    
    if (message == NULL) {
        return NULL;
    }
    
    type = xpc_get_type(message);
    
    if (type == XPC_TYPE_NULL) {
        return kCFNull;
    } else if (type == XPC_TYPE_BOOL) {
        return xpc_bool_get_value(message) ? kCFBooleanTrue : kCFBooleanFalse;
    } else if (type == XPC_TYPE_INT64) {
        int64_t theInt = xpc_int64_get_value(message);
        
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &theInt);
    } else if (type == XPC_TYPE_UINT64) {
        uint64_t theInt = xpc_int64_get_value(message);
        
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &theInt);
    } else if (type == XPC_TYPE_DOUBLE) {
        double theDouble = xpc_double_get_value(message);
        
        return CFNumberCreate(kCFAllocatorDefault, kCFNumberDoubleType, &theDouble);
    } else if (type == XPC_TYPE_DATE) {
        int64_t nsSince1970 = xpc_date_get_value(message);
        
        int64_t sec = nsSince1970 / NSEC_PER_SEC;
        int64_t ns = nsSince1970 % NSEC_PER_SEC;
        
        CFGregorianDate jan1970 = { 1970, 01, 01, 00, 00, 00 };
        CFAbsoluteTime absJan1970 = CFGregorianDateGetAbsoluteTime(jan1970, NULL);
        
        CFAbsoluteTime absTime = absJan1970 + (CFAbsoluteTime)sec + ((CFAbsoluteTime)ns / (CFAbsoluteTime)NSEC_PER_SEC);
        
        return CFDateCreate(kCFAllocatorDefault, absTime);
    } else if (type == XPC_TYPE_DATA) {
        return CFDataCreate(kCFAllocatorDefault, xpc_data_get_bytes_ptr(message), xpc_data_get_length(message));
    } else if (type == XPC_TYPE_STRING) {
        return CFStringCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)xpc_string_get_string_ptr(message), xpc_string_get_length(message), kCFStringEncodingUTF8, false);
    } else if (type == XPC_TYPE_UUID) {
        const uint8_t *uuid = xpc_uuid_get_bytes(message);
        
        return CFUUIDCreateWithBytes(kCFAllocatorDefault, uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    } else if (type == XPC_TYPE_ARRAY) {
        size_t count = xpc_array_get_count(message);
        CFMutableArrayRef array = CFArrayCreateMutable(kCFAllocatorDefault, count, &kCFTypeArrayCallBacks);
        
        for (size_t i = 0; i < count; i++) {
            CFTypeRef theObj = CSASCreateCFTypeFromXPCMessage(xpc_array_get_value(message, i));
            
            if (theObj != NULL) {
                CFArrayAppendValue(array, theObj);
                
                CFRelease(theObj);
            }
        }
        
        return array;
    } else if (type == XPC_TYPE_DICTIONARY) {
        xpc_object_t special;
        
        if ((special = xpc_dictionary_get_value(message, kCSASEncodedURLKey)) != NULL) {
            CFStringRef urlString = CFStringCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)xpc_string_get_string_ptr(special), xpc_string_get_length(special), kCFStringEncodingUTF8, false);
            CFURLRef url = CFURLCreateWithString(kCFAllocatorDefault, urlString, NULL);
            
            CFRelease(urlString);
            
            return url;
        } else if ((special = xpc_dictionary_get_value(message, kCSASEncodedErrorKey)) != NULL) {
            CFStringRef domain = CSASCreateCFTypeFromXPCMessage(xpc_dictionary_get_value(special, kCSASErrorDomainKey));
            int64_t code = xpc_dictionary_get_int64(special, kCSASErrorCodeKey);
            CFDictionaryRef userInfo = CSASCreateCFTypeFromXPCMessage(xpc_dictionary_get_value(special, kCSASErrorUserInfoKey));
            
            CFErrorRef error = CFErrorCreate(kCFAllocatorDefault, domain, code, userInfo);
            
            if (domain != NULL) {
                CFRelease(domain);
            }
            
            if (userInfo != NULL) {
                CFRelease(userInfo);
            }
            
            return error;
        } else {
            size_t count = xpc_dictionary_get_count(message);
            CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, count, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            
            xpc_dictionary_apply(message, ^bool(const char *key, xpc_object_t value) {
                CFStringRef keyString = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
                
                if (keyString != NULL) {
                    CFTypeRef theObj = CSASCreateCFTypeFromXPCMessage(value);
                
                    if (theObj != NULL) {
                        CFDictionarySetValue(dict, keyString, theObj);
                        
                        CFRelease(theObj);
                    }
                
                    CFRelease(keyString);
                }
                
                return true;
            });
            
            return dict;
        }
    }
    
    return NULL;
}

extern xpc_object_t CSASCreateXPCMessageFromCFType(CFTypeRef obj) {
    CFTypeID type;
    
    if (obj == NULL) {
        return NULL;
    }
    
    type = CFGetTypeID(obj);
    
    if (type == CFNullGetTypeID()) {
        return xpc_null_create();
    } else if (type == CFBooleanGetTypeID()) {
        return xpc_bool_create(CFBooleanGetValue(obj));
    } else if (type == CFNumberGetTypeID()) {
        switch (CFNumberGetType(obj)) {
            case kCFNumberFloat32Type:
            case kCFNumberFloat64Type:
            case kCFNumberFloatType:
            case kCFNumberDoubleType:
            case kCFNumberCGFloatType: {
                double theDouble;
                
                if (!CFNumberGetValue(obj, kCFNumberDoubleType, &theDouble)) {
                    theDouble = 0.0;
                }
                
                return xpc_double_create(theDouble);
            }
            default: {
                int64_t theInt;
                
                if (!CFNumberGetValue(obj, kCFNumberSInt64Type, &theInt)) {
                    theInt = 0;
                }
                
                return xpc_int64_create(theInt);
            }
        }
    } else if (type == CFDateGetTypeID()) {
        CFAbsoluteTime absTime = CFDateGetAbsoluteTime(obj);
        
        CFGregorianDate jan1970 = { 1970, 01, 01, 00, 00, 00 };
        CFAbsoluteTime absJan1970 = CFGregorianDateGetAbsoluteTime(jan1970, NULL);
        
        CFAbsoluteTime timeSince1970 = absTime - absJan1970;
        
        double iPart = 0.0;
        double fPart = modf(timeSince1970, &iPart);
        
        int64_t nsSince1970 = (int64_t)iPart * NSEC_PER_SEC + (int64_t)(fPart * (double)NSEC_PER_SEC);
        
        return xpc_date_create(nsSince1970);
    } else if (type == CFDataGetTypeID()) {
        return xpc_data_create(CFDataGetBytePtr(obj), CFDataGetLength(obj));
    } else if (type == CFStringGetTypeID()) {
        CFIndex len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(obj), kCFStringEncodingUTF8) + 1;
        char *string = malloc(len);
        xpc_object_t message = NULL;
        
        if (CFStringGetCString(obj, string, len, kCFStringEncodingUTF8)) {
            message = xpc_string_create(string);
        }
        
        free(string);
        
        return message;
    } else if (type == CFUUIDGetTypeID()) {
        CFUUIDBytes uuidBytes = CFUUIDGetUUIDBytes(obj);
        unsigned char uuid[16] = { uuidBytes.byte0, uuidBytes.byte1, uuidBytes.byte2, uuidBytes.byte3, uuidBytes.byte4, uuidBytes.byte5, uuidBytes.byte6, uuidBytes.byte7, uuidBytes.byte8, uuidBytes.byte9, uuidBytes.byte10, uuidBytes.byte11, uuidBytes.byte12, uuidBytes.byte13, uuidBytes.byte14, uuidBytes.byte15 };
        
        return xpc_uuid_create(uuid);
    } else if (type == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(obj);
        CFTypeRef *objs = malloc(count * sizeof(CFTypeRef));
        xpc_object_t *xpcObjs = malloc(count * sizeof(xpc_object_t));
        size_t xpcCount = 0;
        
        CFArrayGetValues(obj, CFRangeMake(0, count), objs);
        
        for (CFIndex i = 0; i < count; i++) {
            xpc_object_t xpcObj = CSASCreateXPCMessageFromCFType(objs[i]);
            
            if (xpcObj != NULL) {
                xpcObjs[xpcCount++] = xpcObj;
            }
        }
        
        xpc_object_t message = xpc_array_create(xpcObjs, xpcCount);

        for (size_t i = 0; i < xpcCount; i++) {
            xpc_release(xpcObjs[i]);
        }
        
        free(xpcObjs);
        free(objs);
        
        return message;
    } else if (type == CFDictionaryGetTypeID()) {
        CFIndex count = CFDictionaryGetCount(obj);
        CFTypeRef *keys = malloc(count * sizeof(CFTypeRef));
        CFTypeRef *objs = malloc(count * sizeof(CFTypeRef));
        char **xpcKeys = malloc(count * sizeof(char *));
        xpc_object_t *xpcObjs = malloc(count * sizeof(xpc_object_t));
        size_t xpcCount = 0;
        
        CFDictionaryGetKeysAndValues(obj, keys, objs);

        for (CFIndex i = 0; i < count; i++) {
            CFStringRef key = keys[i];
            CFIndex keyLen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(key), kCFStringEncodingUTF8) + 1;
            xpc_object_t xpcObj = NULL;
            char *keyC = malloc(keyLen);
            
            if (CFStringGetCString(key, keyC, keyLen, kCFStringEncodingUTF8)) {
                xpcObj = CSASCreateXPCMessageFromCFType(objs[i]);

                if (xpcObj != NULL) {
                    xpcKeys[xpcCount] = keyC;
                    xpcObjs[xpcCount++] = xpcObj;
                }
            }
            
            if (xpcObj == NULL) {
                free(keyC);
            }
        }
        
        xpc_object_t message = xpc_dictionary_create((const char **)xpcKeys, xpcObjs, xpcCount);
        
        for (size_t i = 0; i < xpcCount; i++) {
            free((void *)xpcKeys[i]);
            xpc_release(xpcObjs[i]);
        }
        
        free(keys);
        free(objs);
        free(xpcKeys);
        free(xpcObjs);
        
        return message;
    } else if (type == CFURLGetTypeID()) {
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, kCSASEncodedURLKey, kCFStringEncodingUTF8);
        CFStringRef value = CFURLGetString(obj);
        
        CFDictionaryRef errorDict = CFDictionaryCreate(kCFAllocatorDefault, (const void **)&key, (const void **)&value, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        
        xpc_object_t message = CSASCreateXPCMessageFromCFType(errorDict);
        
        CFRelease(key);
        
        return message;
    } else if (type == CFErrorGetTypeID()) {
        xpc_object_t domain = CSASCreateXPCMessageFromCFType(CFErrorGetDomain((CFErrorRef)obj));
        xpc_object_t code = xpc_int64_create(CFErrorGetCode((CFErrorRef)obj));
        CFDictionaryRef cfUserInfo = CFErrorCopyUserInfo((CFErrorRef)obj);
        xpc_object_t userInfo = CSASCreateXPCMessageFromCFType(cfUserInfo);
        
        const CFIndex count = 3;
        const char * const keys[count] = { kCSASErrorDomainKey, kCSASErrorCodeKey, kCSASErrorUserInfoKey };
        xpc_object_t values[count] = { domain, code, userInfo };
        
        xpc_object_t errorDict = xpc_dictionary_create(keys, values, count);
        
        xpc_object_t message = xpc_dictionary_create(&kCSASEncodedErrorKey, &errorDict, 1);
        
        if (domain != NULL) {
            xpc_release(domain);
        }
        
        if (code != NULL) {
            xpc_release(code);
        }
        
        if (userInfo != NULL) {
            xpc_release(userInfo);
        }
        
        if (errorDict != NULL) {
            xpc_release(errorDict);
        }
        
        if (cfUserInfo != NULL) {
            CFRelease(cfUserInfo);
        }
        
        return message;
    }
    
    return NULL;
}

extern void CF_FORMAT_FUNCTION(1, 2) CSASLog(CFStringRef format, ...) {
    if (format == NULL) {
        syslog(LOG_NOTICE, "(null)");
        return;
    }
    
    va_list list;
    
    va_start(list, format);
    
    CFStringRef string = CFStringCreateWithFormatAndArguments(kCFAllocatorDefault, NULL, format, list);
    
    va_end(list);
    
    size_t size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(string), kCFStringEncodingUTF8) + 1;
    char *cString = malloc(size);
    CFStringGetCString(string, cString, size, kCFStringEncodingUTF8);
    
    syslog(LOG_NOTICE, "%s", cString);
    
    free(cString);
    CFRelease(string);
}

extern bool CSASFindCommand(
                            CFStringRef                 commandName,
                            const CSASCommandSpec		commands[],
                            size_t *                    commandIndexPtr,
                            CFErrorRef *                errorPtr
                            )
// CSASFindCommand is a simple utility routine for checking that the
// command name within a request is valid (that is, matches one of the command
// names in the CSASCommandSpec array).
//
// On success, *commandIndexPtr will be the index of the requested command
// in the commands array.  On error, the value in *commandIndexPtr is undefined.
{
	bool                        success = true;
    char *                      command;
	CFIndex						commandSize = 0;
	size_t						index = 0;
	
	// Pre-conditions
	
	assert(commandName != NULL);
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
	assert(commandIndexPtr != NULL);
    
    command = NULL;
    
    // Get the command as a C string.  To prevent untrusted command string from
	// trying to run us out of memory, we limit its length to 1024 UTF-16 values.
    
    if ( (commandName == NULL) || (CFGetTypeID(commandName) != CFStringGetTypeID()) ) {
        success = false;
        if (errorPtr != NULL) *errorPtr = CSASCreateCFErrorFromErrno(EINVAL, NULL);
    }
	commandSize = CFStringGetLength(commandName);
	if ( (success) && (commandSize > 1024) ) {
		success = false;
        if (errorPtr != NULL) *errorPtr = CSASCreateCFErrorFromErrno(EINVAL, NULL);
	}
    if (success) {
        size_t      bufSize;
        
        bufSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(commandName), kCFStringEncodingUTF8) + 1;
        command = malloc(bufSize);
        
        if (command == NULL) {
            success = false;
            if (errorPtr != NULL) *errorPtr = CSASCreateCFErrorFromErrno(ENOMEM, NULL);
        } else if ( ! CFStringGetCString(commandName, command, bufSize, kCFStringEncodingUTF8) ) {
            success = false;
            if (errorPtr != NULL) *errorPtr = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
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
                if (errorPtr != NULL) *errorPtr = CSASCreateCFErrorFromErrno(ENOENT, NULL);
                break;
            }
        } while (true);
    }
    
    free(command);
    
	return success;
}
