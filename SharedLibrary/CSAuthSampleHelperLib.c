// CSAuthSampleHelperLib.c
// Copyright Charles Srstka, 2013-2018.
// Based on "BetterAuthorizationSampleLib.c" by Apple Computer.

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

static CFURLRef gHelperURL = NULL;
static CFDictionaryRef gInfoPlist = NULL;

static CSASCommandBlock GetVersionBlock() {
    CFDictionaryRef infoPlist = CSASGetHelperToolInfoPlist();
    CFStringRef version;
    
    assert(infoPlist != NULL);
    
    version = CFDictionaryGetValue(infoPlist, kCFBundleVersionKey);
    
    if (version == NULL) {
        version = CFSTR("0");
    }
    
    return Block_copy(^bool(AuthorizationRef                 auth,
                            __unused CSASCallerCredentials * creds,
                            __unused CFDictionaryRef         request,
                            CFMutableDictionaryRef           response,
                            __unused CFMutableArrayRef       descriptorArray,
                            __unused CSASConnectionHandler * connectionHandler,
                            __unused CFErrorRef *            error) {
        assert(auth != NULL);
        assert(response != NULL);
        
        CFDictionarySetValue(response, CFSTR(kCSASGetVersionResponse), version);
        
        return true;
    });
}

static CSASCommandBlock RemoveHelperBlock() {
    CSASCommandBlock block = Block_copy(^bool(AuthorizationRef                 auth,
                                              __unused CSASCallerCredentials * creds,
                                              __unused CFDictionaryRef         request,
                                              __unused CFMutableDictionaryRef  response,
                                              __unused CFMutableArrayRef       descriptorArray,
                                              __unused CSASConnectionHandler * connectionHandler,
                                              CFErrorRef *                     error) {
        assert(auth != NULL);
        
        const size_t bufsize = PATH_MAX + 1;
        uint8_t helperPath[bufsize];
        
        bool success = true;
        
        if (success && !CFURLGetFileSystemRepresentation(gHelperURL, true, helperPath, bufsize)) {
            if (error) *error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, gHelperURL);
            success = false;
        }
        
        if (success && CFURLResourceIsReachable(gHelperURL, NULL)) {
            if (unlink((const char *)helperPath) != 0) {
                if (error) *error = CSASCreateCFErrorFromErrno(errno, gHelperURL);
                success = false;
            }
        }
        
        return success;
    });
        
    return block;
}

static CFDictionaryRef CSASCreateBuiltInCommandSetWithBlocks() {
    CFDictionaryRef builtInCommands = CSASCreateBuiltInCommandSet();
    CFIndex commandCount = CFDictionaryGetCount(builtInCommands);
    
    CFStringRef *keys = malloc((size_t)commandCount * sizeof(CFStringRef));
    CFDictionaryRef *values = malloc((size_t)commandCount * sizeof(CFDictionaryRef));
    CFDictionaryRef *newValues = malloc((size_t)commandCount * sizeof(CFDictionaryRef));
    
    CFDictionaryRef newCommandSet;
    
    CFIndex i;
    
    CFDictionaryGetKeysAndValues(builtInCommands, (const void **)keys, (const void **)values);
    
    for (i = 0; i < commandCount; i++) {
        CFStringRef name = keys[i];
        CSASCommandBlock commandBlock = NULL;
        
        if (CFEqual(name, CFSTR(kCSASGetVersionCommand))) {
            commandBlock = GetVersionBlock();
        }
        
        if (CFEqual(name, CFSTR(kCSASRemoveHelperCommand))) {
            commandBlock = RemoveHelperBlock();
        }
        
        assert(commandBlock != NULL);
        
        newValues[i] = CSASCommandSpecCreateCopyWithBlock(values[i], commandBlock);
    }
    
    newCommandSet = CFDictionaryCreate(kCFAllocatorDefault, (const void **)keys, (const void **)newValues, commandCount, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    for (i = 0; i < commandCount; i++) {
        CFRelease(newValues[i]);
    }
    
    free(keys);
    free(values);
    free(newValues);
    
    CFRelease(builtInCommands);
    
    return newCommandSet;
}

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

static bool CSASCheckCodeSigningForConnection(xpc_connection_t conn, CFStringRef requirement, CFErrorRef *errorPtr) {
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
        secErr = SecRequirementCreateWithString(requirement, kSecCSDefaultFlags, &secRequirement);
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
        if (errorPtr) *errorPtr = CSASCreateCFErrorFromOSStatus(secErr, NULL);
        return false;
    } else {
        return true;
    }
}

static bool CSASHandleCommand(
                              CFDictionaryRef                commandSet,
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
    CFDictionaryRef             commandSpec = NULL;
    CFMutableDictionaryRef		response	= NULL;
    bool                        success = true;
    CFErrorRef                  error = NULL;
    
    // Pre-conditions
    
    assert(commandSet != NULL);
    assert(CFDictionaryGetCount(commandSet));        // there must be at least one command
    
    // Create a mutable response dictionary before calling the client.
    if (success) {
        response = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (response == NULL) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
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
        
        commandSpec = CFDictionaryGetValue(commandSet, commandName);
        
        if (commandSpec == NULL) {
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
            success = false;
        }
    }
    
    if (success) {
        CFStringRef req = CFDictionaryGetValue(commandSpec, kCSASCommandSpecCodeSigningRequirementKey);
        
        if (req != NULL) {
            success = CSASCheckCodeSigningForConnection(connection, req, &error);
        }
    }
    
    if (success) {
        CFStringRef rightName = CFDictionaryGetValue(commandSpec, kCSASCommandSpecRightNameKey);
        
        // Acquire the associated right for the command.  If rightName is NULL, the
        // commandProc is required to do its own authorization.
        
        if (rightName != NULL) {
            size_t cRightNameSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(rightName), kCFStringEncodingUTF8) + 1;
            char *cRightName = malloc(cRightNameSize);
            
            AuthorizationItem item;
            AuthorizationRights rights;
            
            CFStringGetCString(rightName, cRightName, cRightNameSize, kCFStringEncodingUTF8);
            
            item.name = cRightName;
            item.valueLength = 0;
            item.value = NULL;
            item.flags = 0;
            
            rights.count = 1;
            rights.items = &item;
            
            OSStatus authErr = AuthorizationCopyRights(
                                                       authRef,
                                                       &rights,
                                                       kAuthorizationEmptyEnvironment,
                                                       kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                                                       NULL
                                                       );
            
            free(cRightName);
            
            if (authErr != noErr) {
                success = false;
                
                error = CSASCreateCFErrorFromOSStatus(authErr, NULL);
            }
        }
    }
    
    if (success) {
        CFMutableArrayRef descriptorArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        CSASCallerCredentials creds;
        CSASCommandBlock commandBlock = CFDictionaryGetValue(commandSpec, kCSASCommandSpecExecutionBlockKey);
        
        assert(commandBlock != NULL);
        
        creds.processID = xpc_connection_get_pid(connection);
        creds.userID = xpc_connection_get_euid(connection);
        creds.groupID = xpc_connection_get_egid(connection);
        
        // Call callback to execute command based on the request.
        
        success = commandBlock(authRef, &creds, request, response, descriptorArray, connectionHandler, &error);
        
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
                              CFDictionaryRef           commandSet,
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
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
        }
    }
    
    if (success) {
        remote = xpc_dictionary_get_remote_connection(event);
        
        if (remote == NULL) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
        }
    }
    
    if (success && !isPersistent) {
        commandNameC = xpc_dictionary_get_string(event, kCSASCommandKey);
        
        if (commandNameC == NULL) {
            success = false;
            error = CSASCreateCFErrorFromErrno(EINVAL, NULL);
        }
    }
    
    if (success && !isPersistent) {
        commandName = CFStringCreateWithCString(kCFAllocatorDefault, commandNameC, kCFStringEncodingUTF8);
        
        if (commandName == NULL) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
        }
    }
    
    if (success && !isPersistent) {
        authExtFormData = xpc_dictionary_get_data(event, kCSASAuthorizationRefKey, &authExtFormSize);
        
        if (authExtFormData == NULL || authExtFormSize > sizeof(authExtForm)) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(EINVAL, NULL);
        }
    }
    
    if (success && !isPersistent) {
        memcpy(&authExtForm, authExtFormData, authExtFormSize);
        
        OSStatus authErr = AuthorizationCreateFromExternalForm(&authExtForm, &authRef);
        
        if (authErr != errSecSuccess) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(authErr, NULL);
        } else if (authRef == NULL) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
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
            success = CSASHandleCommand(commandSet, commandName, request, &response, &descriptorArray, authRef, connection, &connectionHandler, &error);
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
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
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
                error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
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
                            CFDictionaryRef             commandSet,
                            xpc_connection_t            connection,
                            xpc_object_t                event
                            )
{
    xpc_type_t type = xpc_get_type(event);
    
    if (type == XPC_TYPE_ERROR) {
        CSASHandleError(connection, event);
    } else if (type == XPC_TYPE_DICTIONARY) {
        CSASHandleRequest(commandSet, connection, event);
    } else {
        syslog(LOG_NOTICE, "Unhandled event");
    }
}

static CFDictionaryRef CSASCreateAuthorizationPrompt(CFDictionaryRef authPrompts, CFStringRef descKey) {
    CFDictionaryRef authPrompt = NULL;
    
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
    }
    
    return authPrompt;
}

static CFDictionaryRef CSASCreateRightForCommandSpec(CFDictionaryRef commandSpec, CFDictionaryRef authPrompts) {
    CFStringRef ruleName = CFDictionaryGetValue(commandSpec, kCSASCommandSpecRightDefaultRuleKey);
    
    if (ruleName == NULL) {
        return NULL;
    } else {
        CFMutableDictionaryRef rightDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFStringRef rightDesc = CFDictionaryGetValue(commandSpec, kCSASCommandSpecRightDescriptionKey);
        CFStringRef rightComment = CFDictionaryGetValue(commandSpec, kCSASCommandSpecRightCommentKey);
        CFDictionaryRef authPrompt = CSASCreateAuthorizationPrompt(authPrompts, rightDesc);
        bool isOneOfOurs = true;
        
        // Replicate all the Apple-supplied rules found in /etc/authorization, but with the "shared" attribute set to false.
        
        if (CFEqual(ruleName, CFSTR(kCSASRuleAllow))) {
            // Allow anyone.
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("allow"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleDeny))) {
            // Deny everyone.
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("deny"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleAuthenticateAdmin))) {
            // Authenticate as admin.
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("admin"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleAuthenticateDeveloper))) {
            // Authenticate as developer.
            
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("_developer"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleAuthenticateSessionOwner))) {
            // Authenticate as session owner.
            
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("session-owner"), kCFBooleanTrue);
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleAuthenticateSessionOwnerOrAdmin))) {
            // Authenticate as admin or session owner.
            
            CFDictionarySetValue(rightDict, CFSTR("allow-root"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("admin"));
            CFDictionarySetValue(rightDict, CFSTR("session-owner"), kCFBooleanTrue);
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleIsAdmin))) {
            // Verify that the user asking for authorization is an administrator.
            
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("admin"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleIsDeveloper))) {
            // Verify that the user asking for authorization is a developer.
            
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("group"), CFSTR("_developer"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleIsRoot))) {
            // Verify that the process that created this AuthorizationRef is running as root.
            
            CFDictionarySetValue(rightDict, CFSTR("allow-root"), kCFBooleanTrue);
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
        } else if (CFEqual(ruleName, CFSTR(kCSASRuleIsSessionOwner))) {
            // Verify that the requesting process is running as the session owner.
            
            CFDictionarySetValue(rightDict, CFSTR("allow-root"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("authenticate-user"), kCFBooleanFalse);
            CFDictionarySetValue(rightDict, CFSTR("class"), CFSTR("user"));
            CFDictionarySetValue(rightDict, CFSTR("session-owner"), kCFBooleanTrue);
        } else {
            CFDictionarySetValue(rightDict, CFSTR("rule"), ruleName);
            
            isOneOfOurs = false;
        }
        
        if (isOneOfOurs) {
            CFNumberRef timeout = CFDictionaryGetValue(commandSpec, kCSASCommandSpecRightTimeoutInSecondsKey);
            
            if (timeout != NULL) {
                CFDictionarySetValue(rightDict, CFSTR("shared"), CFSTR("false"));
                CFDictionarySetValue(rightDict, CFSTR("timeout"), timeout);
            }
        }
        
        if (rightComment != NULL) {
            CFDictionarySetValue(rightDict, CFSTR("comment"), rightComment);
        }
        
        if (authPrompt != NULL) {
            CFDictionarySetValue(rightDict, CFSTR("default-prompt"), authPrompt);
            
            CFRelease(authPrompt);
        }
        
        return rightDict;
    }
}

static void CSASSetDefaultRules(CFDictionaryRef commandSet) {
    AuthorizationRef            auth;
    OSStatus					err;
    CFIndex						commandIndex;
    CFDictionaryRef             authPrompts = NULL;
    CFIndex                     commandCount = CFDictionaryGetCount(commandSet);
    CFDictionaryRef             infoPlist = CSASGetHelperToolInfoPlist();
    
    CFStringRef *               names;
    CFDictionaryRef *           commands;
    
    // Pre-conditions
    
    assert(commandSet != NULL);
    assert(commandCount != 0);        // there must be at least one command
    
    // Get the dictionary containing all the authorization prompts.
    
    if (infoPlist != NULL) {
        authPrompts = CFDictionaryGetValue(infoPlist, CFSTR(kCSASAuthorizationPromptsKey));
    }
    
    // set up the AuthorizationRef
    
    assert(AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &auth) == errSecSuccess);
    
    // For each command, set up the default authorization right specification, as
    // indicated by the command specification.
    
    names = malloc((size_t)commandCount * sizeof(CFStringRef));
    commands = malloc((size_t)commandCount * sizeof(CFDictionaryRef));
    
    CFDictionaryGetKeysAndValues(commandSet, (const void **)names, (const void **)commands);

    for (commandIndex = 0; commandIndex < commandCount; commandIndex++) {
        CFStringRef name = names[commandIndex];
        CFDictionaryRef command = commands[commandIndex];

        CFStringRef rightName = CFDictionaryGetValue(command, kCSASCommandSpecRightNameKey);
        CFStringRef rightDefaultRule = CFDictionaryGetValue(command, kCSASCommandSpecRightDefaultRuleKey);
        CFStringRef rightDesc = CFDictionaryGetValue(command, kCSASCommandSpecRightDescriptionKey);
        
        CFDictionaryRef rightDict = NULL;
        
        // Some no-obvious assertions:
        
        // If you have a right name, you must supply a default rule.
        // If you have no right name, you can't supply a default rule.
        
        assert( (name == NULL) == (rightDefaultRule == NULL) );
        
        // If you have no right name, you can't supply a right description.
        // OTOH, if you have a right name, you may supply a NULL right description
        // (in which case you get no custom prompt).
        
        assert( (name != NULL) || (rightDesc == NULL) );
        
        // Get the right dictionary for our specified right.
        
        rightDict = CSASCreateRightForCommandSpec(command, authPrompts);
        
        // If there's a right name but no current right specification, set up the
        // right specification.
        
        if (rightDict != NULL) {
            CFDictionaryRef existingRight = NULL;
            
            size_t cRightNameSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(rightName), kCFStringEncodingUTF8) + 1;
            char *cRightName = malloc(cRightNameSize);
            
            CFStringGetCString(rightName, cRightName, cRightNameSize, kCFStringEncodingUTF8);
            
            err = AuthorizationRightGet(cRightName, &existingRight);
            
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
                                            cRightName,                                 // rightName
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
            
            free(cRightName);
            CFRelease(rightDict);
        }
    }
    
    free(names);
    free(commands);
    
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
}

static CFDictionaryRef AddBuiltInCommandsToSpecList(CFDictionaryRef inCommandSet) {
    CFMutableDictionaryRef newCommandSet = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, inCommandSet);
    CFDictionaryRef builtInCommandSet = CSASCreateBuiltInCommandSetWithBlocks();
    CFIndex builtInCommandCount = CFDictionaryGetCount(builtInCommandSet);
    
    CFStringRef *names = malloc((size_t)builtInCommandCount * sizeof(CFStringRef));
    CFDictionaryRef *commands = malloc((size_t)builtInCommandCount * sizeof(CFDictionaryRef));
    
    CFIndex i;

    CFDictionaryGetKeysAndValues(builtInCommandSet, (const void **)names, (const void **)commands);
    
    for (i = 0; i < builtInCommandCount; i++) {
        CFDictionarySetValue(newCommandSet, names[i], commands[i]);
    }
    
    free(names);
    free(commands);
    
    CFRelease(builtInCommandSet);
    
    return newCommandSet;
}

extern int CSASHelperToolMain(
                              int                       argc,
                              const char *              argv[],
                              CFDictionaryRef           commandSet,
                              unsigned int              timeoutInterval
                              )
// See comment in header.
{
    CFStringRef                 helperID;
    char                        helperIDC[PATH_MAX];
    
    // Pre-conditions
    
    assert(argc >= 1);
    
    // Get our embedded Info.plist file.
    
    gHelperURL = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)argv[0], strlen(argv[0]), false);
    
    assert(gHelperURL != NULL);
    
    gInfoPlist = CFBundleCopyInfoDictionaryForURL(gHelperURL);
    
    assert(gInfoPlist != NULL);
    
    commandSet = AddBuiltInCommandsToSpecList(commandSet);

    // Set up default rules which other processes must follow to communicate with this tool.
    
    CSASSetDefaultRules(commandSet);
    
    // set up the watchdog stuff
    CSASInitWatchdog(timeoutInterval);
    
    // Set up XPC service.

    helperID = CFDictionaryGetValue(gInfoPlist, kCFBundleIdentifierKey);
    
    if ( helperID == NULL || ! CFStringGetFileSystemRepresentation(helperID, helperIDC, sizeof(helperIDC)) ) {
        exit(EXIT_FAILURE);
    }
    
    xpc_connection_t service = xpc_connection_create_mach_service(helperIDC, NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    
    if (!service) {
        syslog(LOG_NOTICE, "Failed to create service.");
        exit(EXIT_FAILURE);
    }
    
    xpc_connection_set_event_handler(service, ^(xpc_object_t connection) {
        CSASWatchdogDisableAutomaticTermination();
        
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            CSASWatchdogDisableAutomaticTermination();
            
            CSASHandleEvent(commandSet, connection, event);
            
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
     
     return EXIT_SUCCESS;*/
}

extern CFDictionaryRef CSASCommandSpecCreateCopyWithBlock(CFDictionaryRef commandSpec, CSASCommandBlock commandBlock) {
    CFMutableDictionaryRef newCommandSpec = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, commandSpec);
    
    CFDictionarySetValue(newCommandSpec, kCSASCommandSpecExecutionBlockKey, commandBlock);
    
    return newCommandSpec;
}

extern CFDictionaryRef CSASGetHelperToolInfoPlist() {
    return gInfoPlist;
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
