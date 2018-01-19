// CSAuthSampleCommonLib.c
// Copyright Charles Srstka, 2013-2018.
// Based on "BetterAuthorizationSampleLib.c" by Apple Computer.

#include <sys/ucred.h>

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

#include <syslog.h>

//////////////////////////////////////////////////////////////////////////////////
#pragma mark ***** Constants

const CFStringRef kCSASErrorDomain = CFSTR("kCSASErrorDomain");

const CFStringRef kCSASCommandSpecCommandNameKey = CFSTR("CommandName");
const CFStringRef kCSASCommandSpecRightNameKey = CFSTR("RightName");
const CFStringRef kCSASCommandSpecRightDefaultRuleKey = CFSTR("RightDefaultRule");
const CFStringRef kCSASCommandSpecRightTimeoutInSecondsKey = CFSTR("Timeout");
const CFStringRef kCSASCommandSpecRightCommentKey = CFSTR("RightComment");
const CFStringRef kCSASCommandSpecRightDescriptionKey = CFSTR("RightDescription");
const CFStringRef kCSASCommandSpecCodeSigningRequirementKey = CFSTR("CodeSigningRequirement");
const CFStringRef kCSASCommandSpecExecutionBlockKey = CFSTR("ExecutionBlock");

// For encoding NSURLs and NSErrors in a manner that will allow them to be passed along the message port without complaints.

static const char * const kCSASEncodedURLKey = "kCSAuthSampleEncodedeURLKey";
static const char * const kCSASEncodedErrorKey = "kCSASEncodedErrorKey";

/////////////////////////////////////////////////////////////////
#pragma mark ***** Common Code

CFDictionaryRef CSASCommandSpecCreate(CFStringRef commandName,
                                      CFStringRef rightName,
                                      CFStringRef rightDefaultRule,
                                      uint64_t    rightTimeoutInSeconds,
                                      CFStringRef rightComment,
                                      CFStringRef rightDescription,
                                      CFStringRef codeSigningRequirement
                                      ) {
    const size_t maxValueCount = 7;
    size_t valueCount = 0;
    
    CFStringRef *keys = malloc(maxValueCount * sizeof(CFStringRef));
    CFTypeRef *values = malloc(maxValueCount * sizeof(CFTypeRef));
    
    CFNumberRef timeout = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &rightTimeoutInSeconds);
    
    CFDictionaryRef commandSpec;
    
    if (commandName != NULL) {
        keys[valueCount] = kCSASCommandSpecCommandNameKey;
        values[valueCount] = commandName;
        valueCount++;
    }
    
    if (rightName != NULL) {
        keys[valueCount] = kCSASCommandSpecRightNameKey;
        values[valueCount] = rightName;
        valueCount++;
    }
    
    if (rightDefaultRule != NULL) {
        keys[valueCount] = kCSASCommandSpecRightDefaultRuleKey;
        values[valueCount] = rightDefaultRule;
        valueCount++;
    }
    
    if (timeout != NULL) {
        keys[valueCount] = kCSASCommandSpecRightTimeoutInSecondsKey;
        values[valueCount] = timeout;
        valueCount++;
    }
    
    if (rightComment != NULL) {
        keys[valueCount] = kCSASCommandSpecRightCommentKey;
        values[valueCount] = rightComment;
        valueCount++;
    }
    
    if (rightDescription != NULL) {
        keys[valueCount] = kCSASCommandSpecRightDescriptionKey;
        values[valueCount] = rightDescription;
        valueCount++;
    }
    
    if (codeSigningRequirement != NULL) {
        keys[valueCount] = kCSASCommandSpecCodeSigningRequirementKey;
        values[valueCount] = codeSigningRequirement;
        valueCount++;
    }
    
    commandSpec = CFDictionaryCreate(kCFAllocatorDefault, (const void **)keys, (const void **)values, valueCount, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    if (timeout != NULL) {
        CFRelease(timeout);
    }
    
    free(keys);
    free(values);
    
    return commandSpec;
}

static CFMutableDictionaryRef CSASCreateErrorUserInfoForURL(CFURLRef url) {
    CFMutableDictionaryRef userInfo = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    if (url != NULL) {
        CFStringRef scheme = CFURLCopyScheme(url);
        
        CFDictionarySetValue(userInfo, kCFErrorURLKey, url);
        
        if (scheme != NULL && CFEqual(scheme, CFSTR("file"))) {
            CFStringRef path = CFURLCopyPath(url);
            
            CFDictionarySetValue(userInfo, kCFErrorFilePathKey, path);
            
            CFRelease(path);
        }
        
        if (scheme != NULL) {
            CFRelease(scheme);
        }
    }
    
    return userInfo;
}

static CFTimeInterval CSASUNIXEpoch() {
    CFCalendarRef calendar = CFCalendarCreateWithIdentifier(kCFAllocatorDefault, kCFGregorianCalendar);
    CFTimeZoneRef timeZone = CFTimeZoneCreateWithName(kCFAllocatorDefault, CFSTR("UTC"), true);
    CFAbsoluteTime epoch = 0;
    
    CFCalendarSetTimeZone(calendar, timeZone);
    
    CFCalendarComposeAbsoluteTime(calendar, &epoch, "yMdHms", 1970, 1, 1, 0, 0, 0);
    
    CFRelease(timeZone);
    CFRelease(calendar);
    
    return epoch;
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
    bool isFile = scheme != NULL && CFEqual(scheme, CFSTR("file"));
    
    if (scheme != NULL) {
        CFRelease(scheme);
    }
    
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
        
        CFAbsoluteTime absTime = CSASUNIXEpoch() + (CFAbsoluteTime)sec + ((CFAbsoluteTime)ns / (CFAbsoluteTime)NSEC_PER_SEC);
        
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
        
        CFAbsoluteTime timeSince1970 = absTime - CSASUNIXEpoch();
        
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
        
        xpc_object_t message = xpc_dictionary_create((const char * const *)xpcKeys, xpcObjs, xpcCount);
        
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
        CFURLRef url = CFURLCopyAbsoluteURL(obj);
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, kCSASEncodedURLKey, kCFStringEncodingUTF8);
        CFStringRef value = CFURLGetString(url);
        
        CFDictionaryRef errorDict = CFDictionaryCreate(kCFAllocatorDefault, (const void **)&key, (const void **)&value, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        
        xpc_object_t message = CSASCreateXPCMessageFromCFType(errorDict);
        
        CFRelease(key);
        CFRelease(url);
        
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

extern CFDictionaryRef CSASCreateBuiltInCommandSet() {
    const size_t count = 2;
    
    CFStringRef names[count];
    CFDictionaryRef specs[count];
    
    names[0] = CFSTR(kCSASGetVersionCommand);
    specs[0] = CSASCommandSpecCreate(names[0], CFSTR(kCSASGetVersionRightName), CFSTR(kCSASRuleAllow), 0, NULL, NULL, NULL);
    
    names[1] = CFSTR(kCSASRemoveHelperCommand);
    specs[1] = CSASCommandSpecCreate(names[1], CFSTR(kCSASRemoveHelperRightName), CFSTR(kCSASRuleAllow), 0, NULL, NULL, NULL);
    
    CFDictionaryRef newCommandSet = CFDictionaryCreate(kCFAllocatorDefault, (const void **)names, (const void **)specs, count, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    for (size_t i = 0; i < count; i++) {
        CFRelease(specs[i]);
    }
    
    return newCommandSet;
}
