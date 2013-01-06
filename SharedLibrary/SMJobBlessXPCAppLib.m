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

#import "SMJobBlessXPCAppLib.h"

extern void SJBXExecuteRequestInHelperTool(
                                           AuthorizationRef			auth,
                                           const SJBXCommandSpec	commands[],
                                           NSString *				bundleID,
                                           NSDictionary *			request,
                                           void                      (^errorHandler)(NSError *error),
                                           void                      (^replyHandler)(NSDictionary *response)
                                           )
// See comment in header.
{
    bool                        success = true;
    size_t                      commandIndex;
	AuthorizationExternalForm	extAuth;
    xpc_connection_t            connection;
    xpc_object_t 				message;
    CFErrorRef                  error = NULL;
	
	// Pre-conditions
	
	assert(auth != NULL);
	assert(commands != NULL);
	assert(commands[0].commandName != NULL);        // there must be at least one command
    assert(bundleID != NULL);
	assert(request != NULL);
    
	// For debugging.
    
    assert([request[@kSJBXCommandKey] isKindOfClass:[NSString class]]);
    
    // Look up the command and preauthorize.  This has the nice side effect that
    // the authentication dialog comes up, in the typical case, here, rather than
    // in the helper tool.  This is good because the helper tool is global /and/
    // single threaded, so if it's waiting for an authentication dialog for user A
    // it can't handle requests from user B.
    
    success = FindCommand((CFDictionaryRef)request, commands, &commandIndex, &error);
    
    if ( success && (commands[commandIndex].rightName != NULL) ) {
        AuthorizationItem   item   = { commands[commandIndex].rightName, 0, NULL, 0 };
        AuthorizationRights rights = { 1, &item };
        
        OSStatus authErr = AuthorizationCopyRights(auth, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize, NULL);
        
        if (authErr != errSecSuccess) {
            success = false;
            error = SJBXCreateCFErrorFromSecurityError(authErr);
        }
    }
    
    // Open the XPC connection.
        
	if (success) {
		connection = xpc_connection_create_mach_service(bundleID.fileSystemRepresentation, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
		if (connection == NULL) {
            success = false;
            error = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
		}
	}
    
    // Attempt to connect.
    
    if (success) {
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
    
    if (success) {
        message = xpc_dictionary_create(NULL, NULL, 0);
        
        if (message == NULL) {
            success = false;
            error = SJBXCreateCFErrorFromCarbonError(coreFoundationUnknownErr);
        }
    }
	
    // Send the flattened AuthorizationRef to the tool.
    
    if (success) {
        OSStatus authErr = AuthorizationMakeExternalForm(auth, &extAuth);
        
        if (authErr != errSecSuccess) {
            success = false;
            error = SJBXCreateCFErrorFromSecurityError(authErr);
        }
    }
    
	if (success) {
        xpc_dictionary_set_data(message, kSJBXAuthorizationRefKey, &extAuth, sizeof(extAuth));
	}
	
    // Write the request.
    
	if (success) {
		success = SJBXWriteDictionary((CFDictionaryRef)request, message, (CFErrorRef *)&error);
	}
	
    // Send request.
    
    if (success) {
        xpc_connection_send_message_with_reply(connection, message, dispatch_get_main_queue(), ^(xpc_object_t reply) {
            CFDictionaryRef sendResponse = NULL;
            CFErrorRef sendError = NULL;
            
            // Read response.
            
            bool sendSuccess = SJBXReadDictionary(reply, &sendResponse, &sendError);
            
            if (sendSuccess) {
                sendError = SJBXCreateErrorFromResponse(sendResponse);
                
                if (sendError != NULL) {
                    CFRelease(sendResponse);
                    sendSuccess = false;
                }
            }
            
            if (sendSuccess) {
                replyHandler((NSDictionary *)sendResponse);
                CFRelease(sendResponse);
            } else {
                errorHandler((NSError *)sendError);
                CFRelease(sendError);
            }
        });
    }
    
    // If something failed, let the user know.
    
    if (!success) {
        errorHandler((NSError *)error);
        CFRelease(error);
    }
}
