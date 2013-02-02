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

#include "CSAuthSampleHelperLib.h"

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

#include <Security/CodeSigning.h>
#include <syslog.h>

// watchdog stuff

static dispatch_source_t gWatchdogSource = NULL;
static dispatch_queue_t gWatchdogQueue = NULL;

static unsigned int gNumConnections = 0;
static unsigned int gTimeoutInterval = 0;

static void InitWatchdog(unsigned int timeoutInterval) {
    gTimeoutInterval = timeoutInterval;
    gWatchdogQueue = dispatch_queue_create("gWatchdogQueue", DISPATCH_QUEUE_SERIAL);
}

static void ExitIfNoConnections() {
    if (gNumConnections == 0) {
        exit(0);
    }
}

static void CancelWatchdog() {
    if (gWatchdogSource != NULL) {
        dispatch_source_cancel(gWatchdogSource);
        dispatch_release(gWatchdogSource);
        gWatchdogSource = NULL;
    }
}

static void CleanupWatchdog() {
    CancelWatchdog();
    dispatch_release(gWatchdogQueue);
    gWatchdogQueue = NULL;
}

static void RestartWatchdog() {
    if (gTimeoutInterval != 0) {
        gWatchdogSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gWatchdogQueue);
        
        dispatch_source_set_timer(gWatchdogSource, dispatch_time(DISPATCH_TIME_NOW, (int64_t)gTimeoutInterval * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
        
        dispatch_source_set_event_handler(gWatchdogSource, ^{
            ExitIfNoConnections();
        });
        
        dispatch_resume(gWatchdogSource);
    }
}

#if ! defined(NDEBUG)

static bool CommandArraySizeMatchesCommandProcArraySize(
                                                        const CSASCommandSpec		commands[],
                                                        const CSASCommandProc		commandProcs[]
                                                        )
{
    size_t  commandCount;
    size_t  procCount;
    
    commandCount = 0;
    while ( commands[commandCount].commandName != NULL ) {
        commandCount += 1;
    }
    
    procCount = 0;
    while ( commandProcs[procCount] != NULL ) {
        procCount += 1;
    }
    
    return (commandCount == procCount);
}

#endif

// write file descriptors to the XPC message

static bool CSASWriteFileDescriptors(CFArrayRef descriptorArray, xpc_object_t message, __unused __unused CFErrorRef *errorPtr) {
    CFIndex descriptorCount = CFArrayGetCount(descriptorArray);
    bool success = true;
    
    xpc_object_t fdArray = xpc_array_create(NULL, 0);
    
    for (CFIndex i = 0; i < descriptorCount; i++) {
        CFNumberRef eachFdNum = CFArrayGetValueAtIndex(descriptorArray, i);
        int eachFd = 0;
        
        if (!CFNumberGetValue(eachFdNum, kCFNumberIntType, &eachFd)) {
            continue;
        }
        
        xpc_array_set_fd(fdArray, XPC_ARRAY_APPEND, eachFd);
    }
    
    xpc_dictionary_set_value(message, kCSASDescriptorArrayKey, fdArray);
    
    xpc_release(fdArray);
    
    return success;
}

// Close file descriptors after we're done with them

static void CSASCloseFileDescriptors(CFArrayRef descriptorArray) {
    CFIndex descriptorCount = CFArrayGetCount(descriptorArray);
    
    for (CFIndex i = 0; i < descriptorCount; i++) {
        int eachFd;
        
        if (CFNumberGetValue(CFArrayGetValueAtIndex(descriptorArray, i), kCFNumberIntType, &eachFd)) {
            close(eachFd);
        }
    }
}

static bool CheckCodeSigningForConnection(xpc_connection_t conn, const char *requirement, CFErrorRef *errorPtr) {
    SecCodeRef                  secCode = NULL;
    SecRequirementRef           secRequirement = NULL;
    CFDictionaryRef             codeAttrs;
    CFIndex                     pid;
    CFNumberRef                 pidNum;
    CFStringRef                 pidAttrKey;
    OSStatus                    secErr;
    
    // Check the code signing requirement for the command.
    
    pid = xpc_connection_get_pid(conn);
    pidNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberCFIndexType, &pid);
    pidAttrKey = kSecGuestAttributePid;
    
    codeAttrs = CFDictionaryCreate(kCFAllocatorDefault, (const void **)&pidAttrKey, (const void **)&pidNum, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    secErr = SecCodeCopyGuestWithAttributes(NULL, codeAttrs, kSecCSDefaultFlags, &secCode);
    
    if (secErr == errSecSuccess) {
        CFStringRef reqString = CFStringCreateWithCString(kCFAllocatorDefault, requirement, kCFStringEncodingUTF8);
    
        secErr = SecRequirementCreateWithString(reqString, kSecCSDefaultFlags, &secRequirement);
        
        CFRelease(reqString);
    }

    if (secErr == errSecSuccess) {
        secErr = SecCodeCheckValidity(secCode, kSecCSDefaultFlags, secRequirement);
    }
    
    if (codeAttrs != NULL) {
        CFRelease(codeAttrs);
    }
    
    if (pidNum != NULL) {
        CFRelease(pidNum);
    }
    
    if (secCode != NULL) {
        CFRelease(secCode);
    }
    
    if (secRequirement != NULL) {
        CFRelease(secRequirement);
    }
    
    if (secErr != errSecSuccess) {
        if (errorPtr) *errorPtr = CSASCreateCFErrorFromSecurityError(secErr);
        return false;
    } else {
        return true;
    }
}

static bool HandleCommand(
                          const CSASCommandSpec		commands[],
                          const CSASCommandProc		commandProcs[],
                          CFDictionaryRef                request,
                          CFDictionaryRef *              responsePtr,
                          CFArrayRef *                   descriptorArrayPtr,
                          AuthorizationRef               authRef,
                          xpc_connection_t               connection,
                          CFErrorRef *					 errorPtr
                          )
// This routine handles a single connection from a client.  This connection, in
// turn, represents a single command (request/response pair).  commands is the
// list of valid commands.  commandProc is a callback to call to actually
// execute a command.  Finally, fd is the file descriptor from which the request
// should be read, and to which the response should be sent.
{
    size_t                      commandIndex;
    CFMutableDictionaryRef		response	= NULL;
    bool                        success = true;
    CFErrorRef                  error = NULL;
    
    // Pre-conditions
    
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
    assert(commandProcs != NULL);
    assert( CommandArraySizeMatchesCommandProcArraySize(commands, commandProcs) );
    
    // Create a mutable response dictionary before calling the client.
    if (success) {
        response = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (response == NULL) {
            success = false;
            error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
        }
    }
    
    // Errors that occur within this block are considered command errors, that is, they're
    // reported to the client in the kCSASErrorKey value of the response dictionary
    // (that is, CSASExecuteRequestInHelperTool returns noErr and valid response dictionary with
    // an error value in the kCSASErrorKey entry of the dictionary).  In contrast, other errors
    // are considered IPC errors and generally result in a the client getting an error status
    // back from CSASExecuteRequestInHelperTool.
    //
    // Notably a request with an unrecognised command string will return an error code
    // in the response, as opposed to an IPC error.  This means that a client can check
    // whether a tool supports a particular command without triggering an IPC teardown.
    
    if (success) {
        // Get the command name from the request dictionary and check to see whether or
        // not the command is valid by comparing with the CSASCommandSpec array.  Also,
        // if the command is valid, return the associated right (if any).
        
        success = CSASFindCommand(request, commands, &commandIndex, &error);
    }
    
    if (success && (commands[commandIndex].codeSigningRequirement != NULL)) {
        success = CheckCodeSigningForConnection(connection, commands[commandIndex].codeSigningRequirement, &error);
    }
    
    if (success) {
        // Acquire the associated right for the command.  If rightName is NULL, the
		// commandProc is required to do its own authorization.
        
        if (commands[commandIndex].rightName != NULL) {
            AuthorizationItem   item   = { commands[commandIndex].rightName, 0, NULL, 0 };
            AuthorizationRights rights = { 1, &item };
            
            OSStatus authErr = AuthorizationCopyRights(
                                                       authRef,
                                                       &rights,
                                                       kAuthorizationEmptyEnvironment,
                                                       kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                                                       NULL
                                                       );
            
            if (authErr != noErr) {
                success = false;
                
                error = CSASCreateCFErrorFromSecurityError(authErr);
            }
        }
    }
    
    if (success) {
        CFMutableArrayRef descriptorArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        
        // Call callback to execute command based on the request.
        
        success = commandProcs[commandIndex](authRef, commands[commandIndex].userData, request, response, descriptorArray, &error);

        if (descriptorArrayPtr != NULL) {
            if (success && (CFArrayGetCount(descriptorArray) != 0)) {
                *descriptorArrayPtr = descriptorArray;
            } else {
                *descriptorArrayPtr = NULL;
            }
        }
        
        // If the command didn't insert its own error value, we use its function
        // result as the error value.
        
        if ( !success && (error != NULL) && !CFDictionaryContainsKey(response, CFSTR(kCSASErrorKey)) ) {
            CFDictionaryAddValue(response, CFSTR(kCSASErrorKey), error);
        }
    }
    
    // Write response back to the client.
    if (success) {
        *responsePtr = (CFDictionaryRef)response;
    } else {
        if (errorPtr != NULL) {
            *errorPtr = error;
        } else {
            CFRelease(error);
        }
    }
    
    return success;
}

static void HandleEvent(
                        const CSASCommandSpec		commands[],
                        const CSASCommandProc		commandProcs[],
                        xpc_connection_t            connection,
                        xpc_object_t                event
                        )
{
    bool success = true;
    
    xpc_type_t type = xpc_get_type(event);
    
    if (type == XPC_TYPE_ERROR) {
		if (event == XPC_ERROR_CONNECTION_INVALID) {
			// The client process on the other end of the connection has either
			// crashed or cancelled the connection. After receiving this error,
			// the connection is in an invalid state, and you do not need to
			// call xpc_connection_cancel(). Just tear down any associated state
			// here.
            syslog(LOG_NOTICE, "connection went invalid");
		} else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
            syslog(LOG_NOTICE, "Termination imminent");
			// Handle per-connection termination cleanup.
		} else {
            syslog(LOG_NOTICE, "Something went wrong");
        }
	} else if (type == XPC_TYPE_DICTIONARY) {
        CFDictionaryRef request = NULL;
        CFDictionaryRef response = NULL;
        CFArrayRef descriptorArray = NULL;
        xpc_object_t reply = NULL;
        xpc_object_t xpcResponse = NULL;
        xpc_connection_t remote = NULL;
        AuthorizationExternalForm authExtForm;
        const void *authExtFormData;
        size_t authExtFormSize = 0;
        AuthorizationRef authRef = NULL;
        CFErrorRef error = NULL;
        
        if (success) {
            reply = xpc_dictionary_create_reply(event);
            
            if (reply == NULL) {
                success = false;
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
        }
        
        if (success) {
            remote = xpc_dictionary_get_remote_connection(event);
            
            if (remote == NULL) {
                success = false;
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
        }
        
        if (success) {
            authExtFormData = xpc_dictionary_get_data(event, kCSASAuthorizationRefKey, &authExtFormSize);
            
            if (authExtFormData == NULL || authExtFormSize > sizeof(authExtForm)) {
                success = false;
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
        }
        
        if (success) {
            memcpy(&authExtForm, authExtFormData, authExtFormSize);
            
            OSStatus authErr = AuthorizationCreateFromExternalForm(&authExtForm, &authRef);
            
            if (authErr != errSecSuccess) {
                success = false;
                error = CSASCreateCFErrorFromSecurityError(authErr);
            } else if (authRef == NULL) {
                success = false;
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
        }
        
        if (success) {
            xpc_object_t xpcRequest = xpc_dictionary_get_value(event, kCSASRequestKey);
            
            request = CSASCreateCFTypeFromXPCMessage(xpcRequest);
            
            if (request == NULL) {
                success = false;
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
        }
        
        if (success) {
            success = HandleCommand(commands, commandProcs, request, &response, &descriptorArray, authRef, connection, &error);
        }
        
        if (success) {
            xpcResponse = CSASCreateXPCMessageFromCFType(response);
            
            if (xpcResponse == NULL) {
                success = false;
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
        }
        
        if (success && descriptorArray != NULL && CFArrayGetCount(descriptorArray) != 0) {
            success = CSASWriteFileDescriptors(descriptorArray, reply, &error);
        }
        
        if (success) {
            xpc_dictionary_set_value(reply, kCSASRequestKey, xpcResponse);
        }
        
        if (!success) {
            xpc_object_t xpcError;
            CFStringRef errorDesc;
            CFDataRef utf8Error;
            
            if (error == NULL) {
                error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
            }
            
            xpcError = CSASCreateXPCMessageFromCFType((CFTypeRef)error);
            errorDesc = CFCopyDescription(error);
            utf8Error = CFStringCreateExternalRepresentation(kCFAllocatorDefault, errorDesc, kCFStringEncodingUTF8, 0);
            
            syslog(LOG_NOTICE, "Request failed: %s", CFDataGetBytePtr(utf8Error));
            
            xpc_dictionary_set_value(reply, kCSASErrorKey, xpcError);
            
            CFRelease(utf8Error);
            CFRelease(errorDesc);
            xpc_release(xpcError);
        }
    
        if (remote != NULL && reply != NULL) {
            xpc_connection_send_message(remote, reply);
        }
        
        if (descriptorArray != NULL) {
            CSASCloseFileDescriptors(descriptorArray);
            CFRelease(descriptorArray);
        }
        
        if (reply != NULL) {
            xpc_release(reply);
        }
        
        if (response != NULL) {
            CFRelease(response);
        }
        
        if (authRef != NULL) {
            AuthorizationFree(authRef, kAuthorizationFlagDefaults);
        }
        
        if (xpcResponse != NULL) {
            xpc_release(xpcResponse);
        }
        
        if (error != NULL) {
            CFRelease(error);
        }
	} else {
        syslog(LOG_NOTICE, "Unhandled event");
    }
}

static void CSASSetDefaultRules(
                                const CSASCommandSpec		commands[],
                                CFStringRef					bundleID,
                                CFStringRef					descriptionStringTableName
                                )
// See comment in header.
{
    AuthorizationRef            auth;
	OSStatus					err;
    CFBundleRef                 bundle = NULL;
	size_t						commandIndex;
	
	// Pre-conditions
	
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
                                                    // it's not the end of the world if bundleID is NULL
                                                    // descriptionStringTableName may be NULL
    
    if (bundleID != NULL) {
        bundle = CFBundleGetBundleWithIdentifier(bundleID);
    }
    
    // set up the AuthorizationRef
    
    assert(AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth) == errSecSuccess);
	
    // For each command, set up the default authorization right specification, as
    // indicated by the command specification.
    
    commandIndex = 0;
    while (commands[commandIndex].commandName != NULL) {
        // Some no-obvious assertions:
        
        // If you have a right name, you must supply a default rule.
        // If you have no right name, you can't supply a default rule.
        
        assert( (commands[commandIndex].rightName == NULL) == (commands[commandIndex].rightDefaultRule == NULL) );
        
        // If you have no right name, you can't supply a right description.
        // OTOH, if you have a right name, you may supply a NULL right description
        // (in which case you get no custom prompt).
        
        assert( (commands[commandIndex].rightName != NULL) || (commands[commandIndex].rightDescriptionKey == NULL) );
        
        // If there's a right name but no current right specification, set up the
        // right specification.
        
        if (commands[commandIndex].rightName != NULL) {
            Boolean rightNeedsChanging = false;
            CFDictionaryRef existingRight = NULL;
            
            err = AuthorizationRightGet(commands[commandIndex].rightName, &existingRight);
            
            // The original BetterAuthorizationSample code just passes NULL to AuthorizationRightGet, and
            // then checks err against errAuthorizationDenied.
            // This will only set the default rights if they're not already set, but if they're already set
            // (even if they're to wrong or outdated rights), the rights will not be corrected.
            // I, however, want to change the rights if they're not what I want them to be, so check against
            // that and set the rights if something's amiss. Note that the drawback of this is that it can
            // cause annoying password prompts to show up if run from the app, so do this in the helper tool
            // instead. This should be more secure anyway, as it is only run from the (hopefully) incorruptible
            // helper tool code.
            
            if (err == errAuthorizationDenied) {
                rightNeedsChanging = true;
            } else if (err == errAuthorizationSuccess) {
                CFStringRef existingRule = CFDictionaryGetValue(existingRight, CFSTR(kAuthorizationRightRule));
                CFStringRef desiredRule = CFStringCreateWithCString(kCFAllocatorDefault, commands[commandIndex].rightDefaultRule, kCFStringEncodingUTF8);
                
                if (CFStringCompare(existingRule, desiredRule, 0) != kCFCompareEqualTo) {
                    rightNeedsChanging = true;
                }
                
                CFRelease(desiredRule);
                CFRelease(existingRight);
            }
            
            if (rightNeedsChanging) {
                CFStringRef thisDescription;
                CFStringRef	thisRule;
                CFDictionaryRef ruleDict;
                
                // The right is not already defined.  Set up a definition based on
                // the fields in the command specification.
                
                thisRule = CFStringCreateWithCString(
                                                     kCFAllocatorDefault,
                                                     commands[commandIndex].rightDefaultRule,
                                                     kCFStringEncodingUTF8
                                                     );
                assert(thisRule != NULL);
                
                thisDescription = NULL;
                if (commands[commandIndex].rightDescriptionKey != NULL) {
                    thisDescription = CFStringCreateWithCString (
                                                                 kCFAllocatorDefault,
                                                                 commands[commandIndex].rightDescriptionKey,
                                                                 kCFStringEncodingUTF8
                                                                 );
                    assert(thisDescription != NULL);
                }
                
                CFStringRef keys[2] = { CFSTR(kAuthorizationRightRule), CFSTR(kAuthorizationEnvironmentShared) };
                CFTypeRef values[2] = { thisRule, kCFBooleanFalse };
                
                ruleDict = CFDictionaryCreate(kCFAllocatorDefault, (void *)keys, (void *)values, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                
                assert(ruleDict != NULL);
                
                err = AuthorizationRightSet(
                                            auth,										// authRef
                                            commands[commandIndex].rightName,           // rightName
                                            ruleDict,                                   // rightDefinition
                                            thisDescription,							// descriptionKey
                                            bundle,                                     // bundle
                                            descriptionStringTableName					// localeTableName
                                            );												// NULL indicates "Localizable.strings"
                assert(err == noErr);
                
                if (thisDescription != NULL) {
					CFRelease(thisDescription);
				}
                if (thisRule != NULL) {
					CFRelease(thisRule);
				}
                if (ruleDict != NULL) {
                    CFRelease(ruleDict);
                }
            } else {
                // A right already exists (err == noErr) or any other error occurs, we
                // assume that it has been set up in advance by the system administrator or
                // this is the second time we've run.  Either way, there's nothing more for
                // us to do.
            }
        }
        commandIndex += 1;
	}
    
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
}

extern int CSASHelperToolMain(
                              CFStringRef               helperID,
                              CFStringRef               appID,
                              CFStringRef               descriptionStringTableName,
                              const CSASCommandSpec		commands[],
                              const CSASCommandProc		commandProcs[],
                              unsigned int              timeoutInterval
                              )
// See comment in header.
{
    char                        helperIDC[PATH_MAX];
	
	// Pre-conditions
	
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
	assert(commandProcs != NULL);
    assert( CommandArraySizeMatchesCommandProcArraySize(commands, commandProcs) );

    // Set up default rules which other processes must follow to communicate with this tool.
    
    CSASSetDefaultRules(commands, appID, descriptionStringTableName);
    
    // set up the watchdog stuff
    InitWatchdog(timeoutInterval);
    
    // Set up XPC service.
    
    if ( ! CFStringGetFileSystemRepresentation(helperID, helperIDC, sizeof(helperIDC)) ) {
        return EXIT_FAILURE;
    }
    
    xpc_connection_t service = xpc_connection_create_mach_service(helperIDC, NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    
    if (!service) {
        syslog(LOG_NOTICE, "Failed to create service.");
        return EXIT_FAILURE;
    }
    
    xpc_connection_set_event_handler(service, ^(xpc_object_t connection) {
        WatchdogDisableAutomaticTermination();
        
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            WatchdogDisableAutomaticTermination();
            
            HandleEvent(commands, commandProcs, connection, event);
            
            WatchdogEnableAutomaticTermination();
        });
        
        xpc_connection_resume(connection);
        
        WatchdogEnableAutomaticTermination();
	});
    
    xpc_connection_resume(service);
    
    dispatch_main();
    
    // we'll never get here, but eh, release stuff anyway
    
    xpc_release(service);
    
    CleanupWatchdog();
    
    return EXIT_SUCCESS;
}

extern void WatchdogEnableAutomaticTermination() {
    dispatch_sync(gWatchdogQueue, ^{
        CancelWatchdog();
        
        if (gNumConnections > 0) {
            gNumConnections--;
        }
        
        if (gNumConnections == 0) {
            RestartWatchdog();
        }
    });
}

extern void WatchdogDisableAutomaticTermination() {
    dispatch_sync(gWatchdogQueue, ^{
        CancelWatchdog();
        
        gNumConnections++;
    });
}
