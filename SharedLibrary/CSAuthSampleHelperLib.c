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

static void CSASInitWatchdog(unsigned int timeoutInterval) {
    gTimeoutInterval = timeoutInterval;
    gWatchdogQueue = dispatch_queue_create("gWatchdogQueue", DISPATCH_QUEUE_SERIAL);
}

static void CSASExitIfNoConnections() {
    if (gNumConnections == 0) {
        exit(0);
    }
}

static void CSASCancelWatchdog() {
    if (gWatchdogSource != NULL) {
        dispatch_source_cancel(gWatchdogSource);
        dispatch_release(gWatchdogSource);
        gWatchdogSource = NULL;
    }
}

/*static void CSASCleanupWatchdog() {
    CSASCancelWatchdog();
    dispatch_release(gWatchdogQueue);
    gWatchdogQueue = NULL;
}*/

static void CSASRestartWatchdog() {
    if (gTimeoutInterval != 0) {
        gWatchdogSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, gWatchdogQueue);
        
        dispatch_source_set_timer(gWatchdogSource, dispatch_time(DISPATCH_TIME_NOW, (int64_t)gTimeoutInterval * NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
        
        dispatch_source_set_event_handler(gWatchdogSource, ^{
            CSASExitIfNoConnections();
        });
        
        dispatch_resume(gWatchdogSource);
    }
}

#if ! defined(NDEBUG)

static bool CSASCommandArraySizeMatchesCommandProcArraySize(
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

static bool CSASWriteFileDescriptors(CFArrayRef descriptorArray, xpc_object_t message, __unused CFErrorRef *errorPtr) {
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

static bool CSASCheckCodeSigningForConnection(xpc_connection_t conn, const char *requirement, CFErrorRef *errorPtr) {
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

static bool CSASHandleCommand(
                              const CSASCommandSpec		commands[],
                              const CSASCommandProc		commandProcs[],
                              CFStringRef                    commandName,
                              CFDictionaryRef                request,
                              CFDictionaryRef *              responsePtr,
                              CFArrayRef *                   descriptorArrayPtr,
                              AuthorizationRef               authRef,
                              xpc_connection_t               connection,
                              CSASConnectionHandler *        connectionHandler,
                              CFErrorRef *					 errorPtr
                              )
// This routine handles a single connection from a client.  This connection, in
// turn, represents a single command (request/response pair).  commands is the
// list of valid commands.  commandProc is a callback to call to actually
// execute a command.  Finally, fd is the file descriptor from which the request
// should be read, and to which the response should be sent.
{
    size_t                      commandIndex = 0;
    CFMutableDictionaryRef		response	= NULL;
    bool                        success = true;
    CFErrorRef                  error = NULL;
    
    // Pre-conditions
    
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
    assert(commandProcs != NULL);
    assert( CSASCommandArraySizeMatchesCommandProcArraySize(commands, commandProcs) );
    
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
        
        success = CSASFindCommand(commandName, commands, &commandIndex, &error);
    }
    
    if (success && (commands[commandIndex].codeSigningRequirement != NULL)) {
        success = CSASCheckCodeSigningForConnection(connection, commands[commandIndex].codeSigningRequirement, &error);
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
        CSASCallerCredentials creds;
        
        creds.processID = xpc_connection_get_pid(connection);
        creds.userID = xpc_connection_get_euid(connection);
        creds.groupID = xpc_connection_get_egid(connection);
        
        // Call callback to execute command based on the request.
        
        success = commandProcs[commandIndex](authRef, &creds, commands[commandIndex].userData, request, response, descriptorArray, connectionHandler, &error);

        if (descriptorArrayPtr == NULL) {
            CSASCloseFileDescriptors(descriptorArray);
            CFRelease(descriptorArray);
        } else {
            if (success && (CFArrayGetCount(descriptorArray) != 0)) {
                *descriptorArrayPtr = descriptorArray;
            } else {
                *descriptorArrayPtr = NULL;
                CFRelease(descriptorArray);
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

typedef struct CSASXPCConnectionContext {
    CSASConnectionHandler connectionHandler;
} CSASXPCConnectionContext;

static void CSASHandleError(
                            xpc_connection_t connection,
                            xpc_object_t event
                            )
{
    if (event == XPC_ERROR_CONNECTION_INVALID) {
        // The client process on the other end of the connection has either
        // crashed or cancelled the connection. After receiving this error,
        // the connection is in an invalid state, and you do not need to
        // call xpc_connection_cancel(). Just tear down any associated state
        // here.

        CSASXPCConnectionContext *ctx = xpc_connection_get_context(connection);
        
        if (ctx != NULL) {
            if (ctx->connectionHandler != NULL) {
                xpc_release(connection);
                CSASWatchdogEnableAutomaticTermination();

                Block_release(ctx->connectionHandler);
            }
            
            free(ctx);
            xpc_connection_set_context(connection, NULL);
        }
    } else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
        syslog(LOG_NOTICE, "Termination imminent");
        // Handle per-connection termination cleanup.
    } else {
        syslog(LOG_NOTICE, "Something went wrong");
    }
}

static void CSASHandleRequest(
                              const CSASCommandSpec 	commands[],
                              const CSASCommandProc 	commandProcs[],
                              xpc_connection_t      	connection,
                              xpc_object_t          	event
                              )
{
    CFDictionaryRef request = NULL;
    xpc_object_t xpcRequest = NULL;
    CFDictionaryRef response = NULL;
    CFStringRef commandName = NULL;
    const char *commandNameC = NULL;
    CFArrayRef descriptorArray = NULL;
    xpc_object_t reply = NULL;
    xpc_object_t xpcResponse = NULL;
    xpc_connection_t remote = NULL;
    AuthorizationExternalForm authExtForm;
    const void *authExtFormData = NULL;
    size_t authExtFormSize = 0;
    AuthorizationRef authRef = NULL;
    CSASConnectionHandler connectionHandler = NULL;
    CSASXPCConnectionContext *ctx = xpc_connection_get_context(connection);
    bool isPersistent = (ctx != NULL) && (ctx->connectionHandler != NULL);
    bool success = true;
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
    
    if (success && !isPersistent) {
        commandNameC = xpc_dictionary_get_string(event, kCSASCommandKey);
        
        if (commandNameC == NULL) {
            success = false;
            error = CSASCreateCFErrorFromErrno(EINVAL);
        }
    }
    
    if (success && !isPersistent) {
        commandName = CFStringCreateWithCString(kCFAllocatorDefault, commandNameC, kCFStringEncodingUTF8);
        
        if (commandName == NULL) {
            success = false;
            error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
        }
    }
    
    if (success && !isPersistent) {
        authExtFormData = xpc_dictionary_get_data(event, kCSASAuthorizationRefKey, &authExtFormSize);
        
        if (authExtFormData == NULL || authExtFormSize > sizeof(authExtForm)) {
            success = false;
            error = CSASCreateCFErrorFromCarbonError(EINVAL);
        }
    }
    
    if (success && !isPersistent) {
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
        xpcRequest = xpc_dictionary_get_value(event, kCSASRequestKey);
        
        if (xpcRequest != NULL) {
            request = CSASCreateCFTypeFromXPCMessage(xpcRequest);
        }
    }
    
    if (success) {
        if (!isPersistent) {
            success = CSASHandleCommand(commands, commandProcs, commandName, request, &response, &descriptorArray, authRef, connection, &connectionHandler, &error);
        } else if (ctx->connectionHandler != NULL) {
            CFMutableDictionaryRef mutableResponse = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFMutableArrayRef mutableFileDescriptors = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            
            success = ctx->connectionHandler(request, mutableResponse, mutableFileDescriptors, &error);
            
            if (success) {
                response = mutableResponse;
                descriptorArray = mutableFileDescriptors;
            } else {
                CFRelease(mutableResponse);
                CFRelease(mutableFileDescriptors);
            }
        }
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
    
    if (success && (ctx == NULL)) {
        ctx = malloc(sizeof(CSASXPCConnectionContext));
        
        ctx->connectionHandler = connectionHandler;
        
        xpc_connection_set_context(connection, ctx);
        
        if (connectionHandler != NULL) {
            xpc_retain(connection);
            CSASWatchdogDisableAutomaticTermination();
        }
    }
    
    if (success) {
        xpc_dictionary_set_value(reply, kCSASRequestKey, xpcResponse);
        xpc_dictionary_set_bool(reply, kCSASCanAcceptFurtherInputKey, (ctx->connectionHandler != NULL));
    }
    
    if (!success) {
        if (reply != NULL) {
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
        
        if (error != NULL) {
            CFRelease(error);
        }
    }
    
    if (remote != NULL && reply != NULL) {
        xpc_connection_send_message(remote, reply);
    }
    
    if (descriptorArray != NULL) {
        CSASCloseFileDescriptors(descriptorArray);
        CFRelease(descriptorArray);
    }
    
    if (request != NULL) {
        CFRelease(request);
    }
    
    if (reply != NULL) {
        xpc_release(reply);
    }
    
    if (response != NULL) {
        CFRelease(response);
    }
    
    if (commandName != NULL) {
        CFRelease(commandName);
    }
    
    if (authRef != NULL) {
        AuthorizationFree(authRef, kAuthorizationFlagDefaults);
    }
    
    if (xpcResponse != NULL) {
        xpc_release(xpcResponse);
    }
}

static void CSASHandleEvent(
                            const CSASCommandSpec		commands[],
                            const CSASCommandProc		commandProcs[],
                            xpc_connection_t            connection,
                            xpc_object_t                event
                            )
{
    xpc_type_t type = xpc_get_type(event);
    
    if (type == XPC_TYPE_ERROR) {
		CSASHandleError(connection, event);
	} else if (type == XPC_TYPE_DICTIONARY) {
        CSASHandleRequest(commands, commandProcs, connection, event);
	} else {
        syslog(LOG_NOTICE, "Unhandled event");
    }
}

static CFDictionaryRef CSASCreateAuthorizationPrompt(CFDictionaryRef authPrompts, const char *descKeyC) {
    CFDictionaryRef authPrompt = NULL;
    CFStringRef descKey = NULL;
    
    if (descKeyC != NULL) {
        descKey = CFStringCreateWithCString(kCFAllocatorDefault, descKeyC, kCFStringEncodingUTF8);
    }
    
    if (descKey != NULL) {
        if (authPrompts != NULL) {
            // Get the authorization prompt, if there is one, from our Info.plist.
            
            authPrompt = CFDictionaryGetValue(authPrompts, descKey);
        }
        
        if (authPrompt != NULL) {
            CFRetain(authPrompt);
        } else {
            // As a fallback, use the key itself as a non-localized authorization prompt.
            
            CFStringRef key = CFSTR("");
            
            authPrompt = CFDictionaryCreate(kCFAllocatorDefault, (const void **)&key, (const void **)&descKey, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        }
        
        CFRelease(descKey);
    }
    
    return authPrompt;
}

static CFDictionaryRef CSASCreateRightForCommandSpec(CSASCommandSpec commandSpec, CFDictionaryRef authPrompts) {
    const char *ruleName = commandSpec.rightDefaultRule;
    
    if (ruleName == NULL) {
        return NULL;
    } else {
        CFMutableDictionaryRef rightDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionaryRef authPrompt = CSASCreateAuthorizationPrompt(authPrompts, commandSpec.rightDescriptionKey);
        bool isOneOfOurs = true;
        
        // Replicate all the Apple-supplied rules found in /etc/authorization, but with the "shared" attribute set to false.
        
        if (strcmp(ruleName, kCSASRuleAllow) == 0) {
            // Allow anyone.
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("allow"));
        } else if (strcmp(ruleName, kCSASRuleDeny) == 0) {
            // Deny everyone.
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("deny"));
        } else if (strcmp(ruleName, kCSASRuleAuthenticateAdmin) == 0) {
            // Authenticate as admin.
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("admin"));
        } else if (strcmp(ruleName, kCSASRuleAuthenticateDeveloper) == 0) {
            // Authenticate as developer.
            
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("_developer"));
        } else if (strcmp(ruleName, kCSASRuleAuthenticateSessionOwner) == 0) {
            // Authenticate as session owner.
            
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("session-owner"), kCFBooleanTrue);
        } else if (strcmp(ruleName, kCSASRuleAuthenticateSessionOwnerOrAdmin) == 0) {
            // Authenticate as admin or session owner.
            
            CFDictionarySetValue(rightDict, CFSTR("allow-root"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("admin"));
            CFDictionarySetValue(rightDict, CFSTR("session-owner"), kCFBooleanTrue);
        } else if (strcmp(ruleName, kCSASRuleIsAdmin) == 0) {
            // Verify that the user asking for authorization is an administrator.
            
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("admin"));
        } else if (strcmp(ruleName, kCSASRuleIsDeveloper) == 0) {
            // Verify that the user asking for authorization is a developer.
            
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("_developer"));
        } else if (strcmp(ruleName, kCSASRuleIsRoot) == 0) {
            // Verify that the process that created this AuthorizationRef is running as root.
            
            CFDictionarySetValue(rightDict, CFSTR("allow-root"), kCFBooleanTrue);
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
        } else if (strcmp(ruleName, kCSASRuleIsSessionOwner) == 0) {
            // Verify that the requesting process is running as the session owner.
            
            CFDictionarySetValue(rightDict, CFSTR("allow-root"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("session-owner"), kCFBooleanTrue);
        } else {
            CFStringRef nameString = CFStringCreateWithCString(kCFAllocatorDefault, ruleName, kCFStringEncodingUTF8);
            
            CFDictionarySetValue(rightDict, CFSTR("rule"), nameString);
            
            CFRelease(nameString);
            
            isOneOfOurs = false;
        }
        
        if (isOneOfOurs) {
            CFNumberRef timeout = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &commandSpec.rightTimeoutInSeconds);
            
            CFDictionarySetValue(rightDict, CFSTR("shared"), CFSTR("false"));
            CFDictionarySetValue(rightDict, CFSTR("timeout"), timeout);
            
            CFRelease(timeout);
        }
        
        if (commandSpec.rightComment != NULL) {
            CFStringRef comment = CFStringCreateWithCString(kCFAllocatorDefault, commandSpec.rightComment, kCFStringEncodingUTF8);
            
            CFDictionarySetValue(rightDict, CFSTR("comment"), comment);
            
            CFRelease(comment);
        }
        
        if (authPrompt != NULL) {
            CFDictionarySetValue(rightDict, CFSTR("default-prompt"), authPrompt);
            
            CFRelease(authPrompt);
        }
        
        return rightDict;
    }
}

static void CSASSetDefaultRules(
                                const CSASCommandSpec		commands[],
                                CFDictionaryRef             infoPlist
                                )
// See comment in header.
{
    AuthorizationRef            auth;
	OSStatus					err;
	size_t						commandIndex;
	CFDictionaryRef             authPrompts = NULL;
    
	// Pre-conditions
	
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
    
    // Get the dictionary containing all the authorization prompts.
    
    if (infoPlist != NULL) {
        authPrompts = CFDictionaryGetValue(infoPlist, CFSTR(kCSASAuthorizationPromptsKey));
    }
    
    // set up the AuthorizationRef
    
    assert(AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth) == errSecSuccess);
	
    // For each command, set up the default authorization right specification, as
    // indicated by the command specification.
    
    commandIndex = 0;
    while (commands[commandIndex].commandName != NULL) {
        CFDictionaryRef rightDict = NULL;
        
        // Some no-obvious assertions:
        
        // If you have a right name, you must supply a default rule.
        // If you have no right name, you can't supply a default rule.
        
        assert( (commands[commandIndex].rightName == NULL) == (commands[commandIndex].rightDefaultRule == NULL) );
        
        // If you have no right name, you can't supply a right description.
        // OTOH, if you have a right name, you may supply a NULL right description
        // (in which case you get no custom prompt).
        
        assert( (commands[commandIndex].rightName != NULL) || (commands[commandIndex].rightDescriptionKey == NULL) );
        
        // Get the right dictionary for our specified right.
        
        rightDict = CSASCreateRightForCommandSpec(commands[commandIndex], authPrompts);
        
        // If there's a right name but no current right specification, set up the
        // right specification.
        
        if (rightDict != NULL) {
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
                existingRight = NULL;
            }
            
            if (existingRight == NULL || !CFEqual(existingRight, rightDict)) {
                // The right is not already defined.  Set up a definition based on
                // the fields in the command specification.
                
                err = AuthorizationRightSet(
                                            auth,										// authRef
                                            commands[commandIndex].rightName,           // rightName
                                            rightDict,                                  // rightDefinition
                                            NULL,            							// descriptionKey
                                            NULL,                                       // bundle
                                            NULL					                    // localeTableName
                                            );												// NULL indicates "Localizable.strings"

                assert(err == noErr);
            } else {
                // A right already exists (err == noErr) or any other error occurs, we
                // assume that it has been set up in advance by the system administrator or
                // this is the second time we've run.  Either way, there's nothing more for
                // us to do.
            }
            
            if (rightDict != NULL) {
                CFRelease(rightDict);
            }
        }
        commandIndex += 1;
	}
    
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
}

extern int CSASHelperToolMain(
                              int                       argc,
                              const char *              argv[],
                              CFStringRef               helperID,
                              const CSASCommandSpec		commands[],
                              const CSASCommandProc		commandProcs[],
                              unsigned int              timeoutInterval
                              )
// See comment in header.
{
    CFURLRef                    helperURL = NULL;
    CFDictionaryRef             infoPlist = NULL;
    char                        helperIDC[PATH_MAX];
	
	// Pre-conditions
	
    assert(argc >= 1);
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
	assert(commandProcs != NULL);
    assert( CSASCommandArraySizeMatchesCommandProcArraySize(commands, commandProcs) );

    // Get our embedded Info.plist file.
    
    helperURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)argv[0], strlen(argv[0]), false);
    
    assert(helperURL != NULL);
    
    infoPlist = CFBundleCopyInfoDictionaryForURL(helperURL);
    
    assert(infoPlist != NULL);
    
    // Set up default rules which other processes must follow to communicate with this tool.
    
    CSASSetDefaultRules(commands, infoPlist);
    
    // set up the watchdog stuff
    CSASInitWatchdog(timeoutInterval);
    
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
        CSASWatchdogDisableAutomaticTermination();
        
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            CSASWatchdogDisableAutomaticTermination();
            
            CSASHandleEvent(commands, commandProcs, connection, event);
            
            CSASWatchdogEnableAutomaticTermination();
        });
        
        xpc_connection_resume(connection);
        
        CSASWatchdogEnableAutomaticTermination();
	});
    
    xpc_connection_resume(service);
    
    dispatch_main();
    
    // we'll never get here, but eh, release stuff anyway
    // (actually, don't, since the compiler gives a warning that the code will never be executed)
    
    /*xpc_release(service);
    
    CSASCleanupWatchdog();
    
    if (helperURL != NULL) {
        CFRelease(helperURL);
    }
    
    if (infoPlist != NULL) {
        CFRelease(infoPlist);
    }
    
    return EXIT_SUCCESS;*/
}

extern void CSASWatchdogEnableAutomaticTermination() {
    dispatch_sync(gWatchdogQueue, ^{
        CSASCancelWatchdog();
        
        if (gNumConnections > 0) {
            gNumConnections--;
        }
        
        if (gNumConnections == 0) {
            CSASRestartWatchdog();
        }
    });
}

extern void CSASWatchdogDisableAutomaticTermination() {
    dispatch_sync(gWatchdogQueue, ^{
        CSASCancelWatchdog();
        
        gNumConnections++;
    });
}
