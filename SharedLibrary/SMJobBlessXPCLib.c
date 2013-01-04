#include <sys/ucred.h>

/*
 File:       BetterAuthorizationSampleLib.c
 
 Contains:   Implementation of reusable code for privileged helper tools.
 
 Written by: DTS
 
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

// Define SJBX_PRIVATE so that we pick up our private definitions from
// "BetterAuthorizationSampleLib.h".

#define SJBX_PRIVATE 1

#include "SMJobBlessXPCLib.h"

#include <syslog.h>

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

// The key used to get the request dictionary in the XPC request.

#define kSJBXRequestKey              "Request"

// The key used to get our flattened AuthorizationRef in the XPC request.

#define kSJBXAuthorizationRefKey     "AuthorizationRef"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Common Code

extern int SJBXOSStatusToErrno(OSStatus errNum)
// See comment in header.
{
	int retval;
    
#define CASE(ident)         \
case k ## ident ## Err: \
retval = ident;     \
break
    switch (errNum) {
		case noErr:
			retval = 0;
			break;
        case kENORSRCErr:
            retval = ESRCH;                 // no ENORSRC on Mac OS X, so use ESRCH
            break;
        case memFullErr:
            retval = ENOMEM;
            break;
            CASE(EDEADLK);
            CASE(EAGAIN);
		case kEOPNOTSUPPErr:
			retval = ENOTSUP;
			break;
            CASE(EPROTO);
            CASE(ETIME);
            CASE(ENOSR);
            CASE(EBADMSG);
        case kECANCELErr:
            retval = ECANCELED;             // note spelling difference
            break;
            CASE(ENOSTR);
            CASE(ENODATA);
            CASE(EINPROGRESS);
            CASE(ESRCH);
            CASE(ENOMSG);
        default:
            if ( (errNum <= kEPERMErr) && (errNum >= kENOMSGErr) ) {
				retval = (-3200 - errNum) + 1;				// OT based error
            } else if ( (errNum >= errSecErrnoBase) && (errNum <= (errSecErrnoBase + ELAST)) ) {
                retval = (int) errNum - errSecErrnoBase;	// POSIX based error
            } else {
				retval = (int) errNum;						// just return the value unmodified
			}
    }
#undef CASE
    return retval;
}

extern OSStatus SJBXErrnoToOSStatus(int errNum)
// See comment in header.
{
	OSStatus retval;
	
	if ( errNum == 0 ) {
		retval = noErr;
	} else if ( (errNum >= EPERM) && (errNum <= ELAST) ) {
		retval = (OSStatus) errNum + errSecErrnoBase;
	} else {
		retval = (int) errNum;      // just return the value unmodified
	}
    
    return retval;
}

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

static void NormaliseOSStatusErrorCode(OSStatus *errPtr)
// Normalise the cancelled error code to reduce the number of checks that our clients
// have to do.  I made this a function in case I ever want to expand this to handle
// more than just this one case.
{
    assert(errPtr != NULL);
    
    if ( (*errPtr == errAuthorizationCanceled) || (*errPtr == (errSecErrnoBase + ECANCELED)) ) {
        *errPtr = userCanceledErr;
    }
}

static int SJBXReadDictionary(xpc_object_t xpcIn, CFDictionaryRef *dictPtr)
// Create a CFDictionary by reading the XML data from xpcIn.
// It first reads the data in, and then
// unflattens the data into a CFDictionary.
//
// On success, the caller is responsible for releasing *dictPtr.
//
// See also the companion routine, SJBXWriteDictionary, below.
{
	int                 err = 0;
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
	
	if (err == 0) {
        dictBuffer = xpc_dictionary_get_data(xpcIn, kSJBXRequestKey, &dictSize);
        
        if (dictBuffer == NULL) {
            err = SJBXOSStatusToErrno( coreFoundationUnknownErr );
        }
	}
	if ( (err == 0) && SJBXIsBinaryPropertyListData(dictBuffer, dictSize) ) {
        err = SJBXOSStatusToErrno( coreFoundationUnknownErr );
	}
	if (err == 0) {
		dictData = CFDataCreateWithBytesNoCopy(NULL, dictBuffer, dictSize, kCFAllocatorNull);
		if (dictData == NULL) {
			err = SJBXOSStatusToErrno( coreFoundationUnknownErr );
		}
	}
	if (err == 0) {
		dict = CFPropertyListCreateFromXMLData(NULL, dictData, kCFPropertyListImmutable, NULL);
		if (dict == NULL) {
			err = SJBXOSStatusToErrno( coreFoundationUnknownErr );
		}
	}
	if ( (err == 0) && (CFGetTypeID(dict) != CFDictionaryGetTypeID()) ) {
		err = EINVAL;		// only CFDictionaries need apply
	}
	// CFShow(dict);
	
	// Clean up.
	
	if (err != 0) {
		if (dict != NULL) {
			CFRelease(dict);
		}
		dict = NULL;
	}
	*dictPtr = (CFDictionaryRef) dict;

	if (dictData != NULL) {
		CFRelease(dictData);
	}
	
	assert( (err == 0) == (*dictPtr != NULL) );
	
	return err;
}

static int SJBXWriteDictionary(CFDictionaryRef dict, xpc_object_t message)
// Write a dictionary to an XPC message by flattening
// it into XML.
//
// See also the companion routine, SJBXReadDictionary, above.
{
	int                 err = 0;
	CFDataRef			dictData;
    
    // Pre-conditions
    
	assert(dict != NULL);
	assert(message >= 0);
	
	dictData   = NULL;
	
    // Get the dictionary as XML data.
    
	dictData = CFPropertyListCreateXMLData(NULL, dict);
	if (dictData == NULL) {
		err = SJBXOSStatusToErrno( coreFoundationUnknownErr );
	}
    
    // Send the length, then send the data.  Always send the length as a big-endian
    // uint32_t, so that the app and the helper tool can be different architectures.
    //
    // The MoreAuthSample version of this code erroneously assumed that CFDataGetBytePtr
    // can fail and thus allocated an extra buffer to copy the data into.  In reality,
    // CFDataGetBytePtr can't fail, so this version of the code doesn't do the unnecessary
    // allocation.
    
    if ( (err == 0) && (CFDataGetLength(dictData) > kSJBXMaxNumberOfKBytes) ) {
        err = EINVAL;
    }
    
	if (err == 0) {
        xpc_dictionary_set_data(message, kSJBXRequestKey, CFDataGetBytePtr(dictData), CFDataGetLength(dictData));
	}
    
	if (dictData != NULL) {
		CFRelease(dictData);
	}
    
	return err;
}

static OSStatus FindCommand(
                            CFDictionaryRef             request,
                            const SJBXCommandSpec		commands[],
                            size_t *                    commandIndexPtr
                            )
// FindCommand is a simple utility routine for checking that the
// command name within a request is valid (that is, matches one of the command
// names in the SJBXCommandSpec array).
//
// On success, *commandIndexPtr will be the index of the requested command
// in the commands array.  On error, the value in *commandIndexPtr is undefined.
{
	OSStatus					retval = noErr;
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
        retval = paramErr;
    }
	commandSize = CFStringGetLength(commandStr);
	if ( (retval == noErr) && (commandSize > 1024) ) {
		retval = paramErr;
	}
    if (retval == noErr) {
        size_t      bufSize;
        
        bufSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(commandStr), kCFStringEncodingUTF8) + 1;
        command = malloc(bufSize);
        
        if (command == NULL) {
            retval = memFullErr;
        } else if ( ! CFStringGetCString(commandStr, command, bufSize, kCFStringEncodingUTF8) ) {
            retval = coreFoundationUnknownErr;
        }
    }
    
    // Search the commands array for that command.
    
    if (retval == noErr) {
        do {
            if ( strcmp(commands[index].commandName, command) == 0 ) {
                *commandIndexPtr = index;
                break;
            }
            index += 1;
            if (commands[index].commandName == NULL) {
                retval = SJBXErrnoToOSStatus(ENOENT);
                break;
            }
        } while (true);
    }
    
    free(command);
    
	return retval;
}

/////////////////////////////////////////////////////////////////
#pragma mark ***** Tool Code

#if ! defined(NDEBUG)

static bool CommandArraySizeMatchesCommandProcArraySize(
                                                        const SJBXCommandSpec		commands[],
                                                        const SJBXCommandProc		commandProcs[]
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

static int HandleCommand(
                         const SJBXCommandSpec		commands[],
                         const SJBXCommandProc		commandProcs[],
                         CFDictionaryRef                request,
                         CFDictionaryRef                *responsePtr,
                         AuthorizationRef               authRef
                         )
// This routine handles a single connection from a client.  This connection, in
// turn, represents a single command (request/response pair).  commands is the
// list of valid commands.  commandProc is a callback to call to actually
// execute a command.  Finally, fd is the file descriptor from which the request
// should be read, and to which the response should be sent.
{
    int                         retval = 0;
    size_t                      commandIndex;
    CFMutableDictionaryRef		response	= NULL;
    OSStatus                    commandProcStatus;
    
    // Pre-conditions
    
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
    assert(commandProcs != NULL);
    assert( CommandArraySizeMatchesCommandProcArraySize(commands, commandProcs) );
    
    // Create a mutable response dictionary before calling the client.
    if (retval == 0) {
        response = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (response == NULL) {
            retval = SJBXOSStatusToErrno( coreFoundationUnknownErr );
        }
    }
    
    // Errors that occur within this block are considered command errors, that is, they're
    // reported to the client in the kSJBXErrorKey value of the response dictionary
    // (that is, SJBXExecuteRequestInHelperTool returns noErr and valid response dictionary with
    // an error value in the kSJBXErrorKey entry of the dictionary).  In contrast, other errors
    // are considered IPC errors and generally result in a the client getting an error status
    // back from SJBXExecuteRequestInHelperTool.
    //
    // Notably a request with an unrecognised command string will return an error code
    // in the response, as opposed to an IPC error.  This means that a client can check
    // whether a tool supports a particular command without triggering an IPC teardown.
    
    if (retval == 0) {
        // Get the command name from the request dictionary and check to see whether or
        // not the command is valid by comparing with the SJBXCommandSpec array.  Also,
        // if the command is valid, return the associated right (if any).
        
        commandProcStatus = FindCommand(request, commands, &commandIndex);
        
        // Acquire the associated right for the command.  If rightName is NULL, the
		// commandProc is required to do its own authorization.
        
        if ( (commandProcStatus == noErr) && (commands[commandIndex].rightName != NULL) ) {
            AuthorizationItem   item   = { commands[commandIndex].rightName, 0, NULL, 0 };
            AuthorizationRights rights = { 1, &item };

            commandProcStatus = AuthorizationCopyRights(
                                                        authRef,
                                                        &rights,
                                                        kAuthorizationEmptyEnvironment,
                                                        kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                                                        NULL
                                                        );
        }
        
        // Call callback to execute command based on the request.
        
        if (commandProcStatus == noErr) {
            commandProcStatus = commandProcs[commandIndex](authRef, commands[commandIndex].userData, request, response);
            
            if (commandProcStatus == noErr) {
                syslog(LOG_DEBUG, "Command callback succeeded");
            } else {
                syslog(LOG_DEBUG, "Command callback failed: %ld", (long) commandProcStatus);
            }
        }
        
        // If the command didn't insert its own error value, we use its function
        // result as the error value.
        
        if ( ! CFDictionaryContainsKey(response, CFSTR(kSJBXErrorKey)) ) {
            CFNumberRef     numRef;
            
            numRef = CFNumberCreate(NULL, kCFNumberSInt32Type, &commandProcStatus);
            if (numRef == NULL) {
                retval = SJBXOSStatusToErrno( coreFoundationUnknownErr );
            } else {
                CFDictionaryAddValue(response, CFSTR(kSJBXErrorKey), numRef);
                CFRelease(numRef);
            }
        }
    }
    
    // Write response back to the client.
    if (retval == 0) {
        *responsePtr = (CFDictionaryRef)response;
    }
        
    return retval;
}

static int HandleEvent(
                       const SJBXCommandSpec		commands[],
                       const SJBXCommandProc		commandProcs[],
                       xpc_object_t                 event
                       )
{
    int err = 0;
    
    xpc_type_t type = xpc_get_type(event);
    
    if (type == XPC_TYPE_ERROR) {
        syslog(LOG_NOTICE, "An error occurred");
        
		if (event == XPC_ERROR_CONNECTION_INVALID) {
			// The client process on the other end of the connection has either
			// crashed or cancelled the connection. After receiving this error,
			// the connection is in an invalid state, and you do not need to
			// call xpc_connection_cancel(). Just tear down any associated state
			// here.
            syslog(LOG_NOTICE, "Invalid connection");
		} else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
            syslog(LOG_NOTICE, "Termination imminent");
			// Handle per-connection termination cleanup.
		}
	} else if (type == XPC_TYPE_DICTIONARY) {
        CFDictionaryRef request = NULL;
        CFDictionaryRef response = NULL;
        xpc_object_t reply = NULL;
        xpc_connection_t remote = NULL;
        AuthorizationExternalForm authExtForm;
        const void *authExtFormData;
        size_t authExtFormSize = 0;
        AuthorizationRef authRef = NULL;
        
        authExtFormData = xpc_dictionary_get_data(event, kSJBXAuthorizationRefKey, &authExtFormSize);
        
        if (authExtFormData == NULL || authExtFormSize > sizeof(authExtForm)) {
            err = SJBXOSStatusToErrno(coreFoundationUnknownErr);
        }
        
        if (err == 0) {
            memcpy(&authExtForm, authExtFormData, authExtFormSize);
            
            err = SJBXOSStatusToErrno(AuthorizationCreateFromExternalForm(&authExtForm, &authRef));
            
            if (authRef == NULL) {
                err = SJBXOSStatusToErrno(coreFoundationUnknownErr);
            }
        }
        
        if (err == 0) {
            err = SJBXReadDictionary(event, &request);
        }
        
        if (err == 0) {
            err = HandleCommand(commands, commandProcs, request, &response, authRef);
        }
        
        if (err == 0) {
            reply = xpc_dictionary_create_reply(event);

            err = SJBXWriteDictionary(response, reply);
        }
        
        if (err == 0) {
            remote = xpc_dictionary_get_remote_connection(event);
            
            if (remote == NULL) {
                err = SJBXOSStatusToErrno(coreFoundationUnknownErr);
            }
        }
        
        if (err == 0) {
            xpc_connection_send_message(remote, reply);
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
	} else {
        syslog(LOG_NOTICE, "Unhandled event");
    }
    
    return err;
}

extern int SJBXHelperToolMain(
                                 CFStringRef                    helperID,
                                 const SJBXCommandSpec		commands[],
                                 const SJBXCommandProc		commandProcs[]
                                 )
// See comment in header.
{
    char                        helperIDC[PATH_MAX];
	
	// Pre-conditions
	
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
	assert(commandProcs != NULL);
    assert( CommandArraySizeMatchesCommandProcArraySize(commands, commandProcs) );
    
    // Set up XPC service.
    
    if ( ! CFStringGetFileSystemRepresentation(helperID, helperIDC, sizeof(helperIDC)) ) {
        return EXIT_FAILURE;
    }
    
    xpc_connection_t service = xpc_connection_create_mach_service(helperIDC, dispatch_get_main_queue(), XPC_CONNECTION_MACH_SERVICE_LISTENER);

    if (!service) {
        syslog(LOG_NOTICE, "Failed to create service.");
        return EXIT_FAILURE;
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t connection) {
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            int thisConnectionError = HandleEvent(commands, commandProcs, event);
            
            if (thisConnectionError != 0) {
                errno = thisConnectionError;
                syslog(LOG_NOTICE, "Request failed: %m");
            }
        });
        
        xpc_connection_resume(connection);
	});
    
    xpc_connection_resume(service);

    dispatch_main();
    
    xpc_release(service);
    
    return EXIT_SUCCESS;
}

/////////////////////////////////////////////////////////////////
#pragma mark ***** App Code

extern void SJBXSetDefaultRules(
                                   AuthorizationRef			auth,
                                   const SJBXCommandSpec		commands[],
                                   CFStringRef					bundleID,
                                   CFStringRef					descriptionStringTableName
                                   )
// See comment in header.
{
	OSStatus					err;
    CFBundleRef                 bundle;
	size_t						commandIndex;
	
	// Pre-conditions
	
	assert(auth != NULL);
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
	assert(bundleID != NULL);
    // descriptionStringTableName may be NULL
    
    bundle = CFBundleGetBundleWithIdentifier(bundleID);
    assert(bundle != NULL);
	
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
            // cause annoying password prompts to show up.
            
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
                
                err = AuthorizationRightSet(
                                            auth,										// authRef
                                            commands[commandIndex].rightName,           // rightName
                                            thisRule,                                   // rightDefinition
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
            } else {
                // A right already exists (err == noErr) or any other error occurs, we
                // assume that it has been set up in advance by the system administrator or
                // this is the second time we've run.  Either way, there's nothing more for
                // us to do.
            }
        }
        commandIndex += 1;
	}
}

extern OSStatus SJBXExecuteRequestInHelperTool(
                                                  AuthorizationRef			auth,
                                                  const SJBXCommandSpec	commands[],
                                                  CFStringRef				bundleID,
                                                  CFDictionaryRef			request,
                                                  void                      (^errorHandler)(CFErrorRef error),
                                                  void                      (^replyHandler)(CFDictionaryRef response)
                                                  )
// See comment in header.
{
	OSStatus					retval = noErr;
    size_t                      commandIndex;
    char                        bundleIDC[PATH_MAX];
	AuthorizationExternalForm	extAuth;
    xpc_connection_t            connection;
    xpc_object_t 				message;
	
	// Pre-conditions
	
	assert(auth != NULL);
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
    assert(bundleID != NULL);
	assert(request != NULL);
    
	// For debugging.
    
	assert(CFDictionaryContainsKey(request, CFSTR(kSJBXCommandKey)));
	assert(CFGetTypeID(CFDictionaryGetValue(request, CFSTR(kSJBXCommandKey))) == CFStringGetTypeID());
    
    // Look up the command and preauthorize.  This has the nice side effect that
    // the authentication dialog comes up, in the typical case, here, rather than
    // in the helper tool.  This is good because the helper tool is global /and/
    // single threaded, so if it's waiting for an authentication dialog for user A
    // it can't handle requests from user B.
    
    retval = FindCommand(request, commands, &commandIndex);
    
    if ( (retval == noErr) && (commands[commandIndex].rightName != NULL) ) {
        AuthorizationItem   item   = { commands[commandIndex].rightName, 0, NULL, 0 };
        AuthorizationRights rights = { 1, &item };

        retval = AuthorizationCopyRights(auth, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize, NULL);
    }
    
    // Open the XPC connection.
    
    if (retval == noErr) {
        if ( ! CFStringGetFileSystemRepresentation(bundleID, bundleIDC, sizeof(bundleIDC)) ) {
            retval = coreFoundationUnknownErr;
        }
    }
    
	if (retval == noErr) {
		connection = xpc_connection_create_mach_service(bundleIDC, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
		if (connection == NULL) {
			retval = coreFoundationUnknownErr;
		}
	}
    
    // Attempt to connect.
    
    if (retval == noErr) {
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            xpc_type_t type = xpc_get_type(event);
            
            if (type == XPC_TYPE_ERROR) {
                if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                    //[self appendLog:@"XPC connection interupted."];
                    
                } else if (event == XPC_ERROR_CONNECTION_INVALID) {
                    //[self appendLog:@"XPC connection invalid, releasing."];
                    xpc_release(connection);
                    
                } else {
                    //[self appendLog:@"Unexpected XPC connection error."];
                }
                
            } else {
                //[self appendLog:@"Unexpected XPC connection event."];
            }
        });
        
        xpc_connection_resume(connection);
	}
    
    // Create an XPC dictionary object.
    
    if (retval == noErr) {
        message = xpc_dictionary_create(NULL, NULL, 0);
        
        if (message == NULL) {
            retval = coreFoundationUnknownErr;
        }
    }
	
    // Send the flattened AuthorizationRef to the tool.
    
    if (retval == noErr) {
        retval = AuthorizationMakeExternalForm(auth, &extAuth);
    }
    
	if (retval == noErr) {
        xpc_dictionary_set_data(message, kSJBXAuthorizationRefKey, &extAuth, sizeof(extAuth));
	}
	
    // Write the request.
    
	if (retval == noErr) {
		retval = SJBXErrnoToOSStatus( SJBXWriteDictionary(request, message) );
	}
	
    // Send request.
    
    if (retval == noErr) {
        xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t reply) {
            CFDictionaryRef dict = NULL;
            CFErrorRef error = NULL;
            
            // Read response.
            
            int err = SJBXReadDictionary(reply, &dict);
            
            if (err != 0) {
                dict = NULL;
                error = CFErrorCreate(kCFAllocatorDefault, kCFErrorDomainPOSIX, err, NULL);
            }
            
            if (dict) {
                replyHandler(dict);
                CFRelease(dict);
            }
            
            if (error) {
                errorHandler(error);
                CFRelease(error);
            }
        });
    }
    
    // Clean up.
    
    NormaliseOSStatusErrorCode(&retval);
    
	return retval;
}

extern OSStatus SJBXGetErrorFromResponse(CFDictionaryRef response)
// See comment in header.
{
	OSStatus	err;
	CFNumberRef num;
	
	assert(response != NULL);
	
	num = (CFNumberRef) CFDictionaryGetValue(response, CFSTR(kSJBXErrorKey));
    err = noErr;
    if ( (num == NULL) || (CFGetTypeID(num) != CFNumberGetTypeID()) ) {
        err = coreFoundationUnknownErr;
    }
	if (err == noErr) {
		if ( ! CFNumberGetValue(num, kCFNumberSInt32Type, &err) ) {
            err = coreFoundationUnknownErr;
        }
	}
	
    NormaliseOSStatusErrorCode(&err);
	return err;
}
