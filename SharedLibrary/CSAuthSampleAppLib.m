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

#import "CSAuthSampleAppLib.h"
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Authorization.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(objc_arc)
#define USING_ARC           1
#endif

#if USING_ARC
#define RELEASE(x)
#define BRIDGE(type, var)   ((__bridge type)(var))
#define BRIDGING_RETAIN(x)  CFBridgingRetain(x)
#define BRIDGING_RELEASE(x) CFBridgingRelease(x)
#define SUPER_DEALLOC
#else
#define RELEASE(x)          [(x) release]
#define BRIDGE(type, var)   ((type)(var))
#define BRIDGING_RETAIN(x)  ((CFTypeRef)[(x) retain])
#define BRIDGING_RELEASE(x) [(id)(x) autorelease]
#define SUPER_DEALLOC       [super dealloc]
#endif

#if USING_ARC && OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#define RELEASE_XPC(x)
#else
#define RELEASE_XPC(x)      xpc_release(x)
#endif

@interface CSASCommandSender ()

@property (copy) NSString *helperID;

@end

@implementation CSASCommandSender {
    AuthorizationRef _authRef;
    const CSASCommandSpec *_commands;
}

- (instancetype)initWithCommandSet:(const CSASCommandSpec *)commands helperID:(NSString *)helperID error:(NSError **)error {
    self = [super init];
    
    if (self == nil) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadUnknownError userInfo:nil];
        return nil;
    }
    
    OSStatus err = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &_authRef);
    
    if (err != errSecSuccess) {
        if (error) *error = (NSError *)BRIDGING_RELEASE(CSASCreateCFErrorFromSecurityError(err));
        RELEASE(self);
        return nil;
    }
    
    if (_authRef == NULL || helperID == nil || commands == NULL || commands[0].commandName == NULL) { // there must be at least one command
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
        RELEASE(self);
        return nil;
    }
    
    _commands = commands;
    _helperID = [helperID copy];
    
    return self;
}

- (void)dealloc {
    [self cleanUp];
    
    RELEASE(_helperID);
    
    SUPER_DEALLOC;
}

- (void)cleanUp {
    if (_authRef != NULL) {
        // destroy rights for a little added security
        AuthorizationFree(_authRef, kAuthorizationFlagDestroyRights);
    }
}

- (NSArray *)fileHandlesFromXPCReply:(xpc_object_t)reply {
    NSMutableArray *handleArray = [NSMutableArray new];
    xpc_object_t descriptorArray = xpc_dictionary_get_value(reply, kCSASDescriptorArrayKey);
    size_t descriptorCount = 0;
    
    if (descriptorArray != NULL) {
        descriptorCount = xpc_array_get_count(descriptorArray);
    }
    
    if (descriptorCount != 0) {
        for (size_t i = 0; i < descriptorCount; i++) {
            int fd = xpc_array_dup_fd(descriptorArray, i);
            
            if (fd < 0) {
                continue;
            }
            
            [handleArray addObject:[[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES]];
        }
    }
    
    return handleArray;
}

- (BOOL)blessHelperToolAndReturnError:(NSError **)error {
	BOOL success = NO;
    
	AuthorizationItem authItem		= { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
	AuthorizationRights authRights	= { 1, &authItem };
	AuthorizationFlags flags		= (kAuthorizationFlagDefaults             |
                                       kAuthorizationFlagInteractionAllowed	|
                                       kAuthorizationFlagPreAuthorize			|
                                       kAuthorizationFlagExtendRights
                                       );
	
	/* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
    OSStatus status = AuthorizationCopyRights(_authRef, &authRights, kAuthorizationEmptyEnvironment, flags, NULL);
	if (status != errAuthorizationSuccess) {
        if (error) *error = (NSError *)BRIDGING_RELEASE(CSASCreateCFErrorFromSecurityError(status));
        success = NO;
	} else {
        CFErrorRef smError = NULL;
        
        SMJobRemove(kSMDomainSystemLaunchd, BRIDGE(CFStringRef, self.helperID), _authRef, YES, NULL);
        
        /* This does all the work of verifying the helper tool against the application
		 * and vice-versa. Once verification has passed, the embedded launchd.plist
		 * is extracted and placed in /Library/LaunchDaemons and then loaded. The
		 * executable is placed in /Library/PrivilegedHelperTools.
		 */
		success = SMJobBless(kSMDomainSystemLaunchd, BRIDGE(CFStringRef, self.helperID), _authRef, &smError);
        
        if (!success) {
            if (error) *error = BRIDGING_RELEASE(smError);
        }
    }
	
	return success;
}

- (void)executeRequestInHelperTool:(NSDictionary *)request errorHandler:(CSASErrorHandler)errorHandler responseHandler:(CSASResponseHandler)responseHandler {
    bool                        success = true;
    size_t                      commandIndex;
	AuthorizationExternalForm	extAuth;
    xpc_connection_t            connection;
    xpc_object_t 				message;
    CFErrorRef                  error = NULL;
    __block NSError *           connectionError = nil;
	
	// Pre-conditions
	
	assert(request != nil);
    
	// For debugging.
    
    assert([request[@kCSASCommandKey] isKindOfClass:[NSString class]]);
    
    // Look up the command and preauthorize.  This has the nice side effect that
    // the authentication dialog comes up, in the typical case, here, rather than
    // in the helper tool.  This is good because the helper tool is global /and/
    // single threaded, so if it's waiting for an authentication dialog for user A
    // it can't handle requests from user B.
    
    success = FindCommand(BRIDGE(CFDictionaryRef, request), _commands, &commandIndex, &error);
    
    if ( success && (_commands[commandIndex].rightName != NULL) ) {
        AuthorizationItem   item   = { _commands[commandIndex].rightName, 0, NULL, 0 };
        AuthorizationRights rights = { 1, &item };
        
        OSStatus authErr = AuthorizationCopyRights(_authRef, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize, NULL);
        
        if (authErr != errSecSuccess) {
            success = false;
            error = CSASCreateCFErrorFromSecurityError(authErr);
        }
    }
    
    // Open the XPC connection.
        
	if (success) {
		connection = xpc_connection_create_mach_service(self.helperID.fileSystemRepresentation, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
		if (connection == NULL) {
            success = false;
            error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
		}
	}
    
    // Attempt to connect.
    
    if (success) {
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            xpc_type_t type = xpc_get_type(event);
            
            if (type == XPC_TYPE_ERROR) {
                if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                    if (connectionError == nil) {
                        connectionError = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorConnectionInterrupted userInfo:nil];
                    }
                } else if (event == XPC_ERROR_CONNECTION_INVALID) {
                    if (connectionError == nil) {
                        connectionError = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorConnectionInvalid userInfo:nil];
                    }
                } else {
                    if (connectionError == nil) {
                        connectionError = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorUnexpectedConnection userInfo:nil];
                    }
                }
            } else {
                if (connectionError == nil) {
                    connectionError = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorUnexpectedEvent userInfo:nil];
                }
            }
        });
        
        xpc_connection_resume(connection);
	}
    
    // Create an XPC dictionary object.
    
    if (success) {
        message = xpc_dictionary_create(NULL, NULL, 0);
        
        if (message == NULL) {
            success = false;
            error = CSASCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
        }
    }
	
    // Send the flattened AuthorizationRef to the tool.
    
    if (success) {
        OSStatus authErr = AuthorizationMakeExternalForm(_authRef, &extAuth);
        
        if (authErr != errSecSuccess) {
            success = false;
            error = CSASCreateCFErrorFromSecurityError(authErr);
        }
    }
    
	if (success) {
        xpc_dictionary_set_data(message, kCSASAuthorizationRefKey, &extAuth, sizeof(extAuth));
	}
	
    // Write the request.
    
	if (success) {
		success = CSASWriteDictionary(BRIDGE(CFDictionaryRef, request), message, (CFErrorRef *)&error);
	}
	
    // Send request.
    
    if (success) {
        xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t reply) {
            CFDictionaryRef sendResponse = NULL;
            NSArray *fileHandles = nil;
            CFErrorRef sendError = NULL;
            
            // Read response.
            
            bool sendSuccess = CSASReadDictionary(reply, &sendResponse, &sendError);
            
            if (sendSuccess) {
                sendError = CSASCreateErrorFromResponse(sendResponse);
                
                if (sendError != NULL) {
                    CFRelease(sendResponse);
                    sendSuccess = false;
                }
            }
            
            if (sendSuccess) {
                fileHandles = [self fileHandlesFromXPCReply:reply];
            }
            
            if (sendSuccess) {
                if (responseHandler != nil) responseHandler(BRIDGE(NSDictionary *, sendResponse), fileHandles);
                CFRelease(sendResponse);
            } else {
                if (connectionError != nil) {
                    if (errorHandler != nil) errorHandler(connectionError);
                } else {
                    if (errorHandler != nil) errorHandler(BRIDGE(NSError *, sendError));
                }
                
                CFRelease(sendError);
            }
            
            RELEASE(fileHandles);
            RELEASE_XPC(connection);
        });
    }
    
    // If something failed, let the user know.
    
    if (!success) {
        if (errorHandler != nil) errorHandler(BRIDGE(NSError *, error));
        CFRelease(error);
        RELEASE_XPC(connection);
    }
}

@end
