/*
 
    File: SMJobBlessAppController.m
Abstract: The main application controller. When the application has finished
launching, the helper tool will be installed.
 Version: 1.2

Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple
Inc. ("Apple") in consideration of your agreement to the following
terms, and your use, installation, modification or redistribution of
this Apple software constitutes acceptance of these terms.  If you do
not agree with these terms, please do not use, install, modify or
redistribute this Apple software.

In consideration of your agreement to abide by the following terms, and
subject to these terms, Apple grants you a personal, non-exclusive
license, under Apple's copyrights in this original Apple software (the
"Apple Software"), to use, reproduce, modify and redistribute the Apple
Software, with or without modifications, in source and/or binary forms;
provided that if you redistribute the Apple Software in its entirety and
without modifications, you must retain this notice and the following
text and disclaimers in all such redistributions of the Apple Software.
Neither the name, trademarks, service marks or logos of Apple Inc. may
be used to endorse or promote products derived from the Apple Software
without specific prior written permission from Apple.  Except as
expressly stated in this notice, no other rights or licenses, express or
implied, are granted by Apple herein, including but not limited to any
patent rights that may be infringed by your derivative works or by other
works in which the Apple Software may be incorporated.

The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.

IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Copyright (C) 2011 Apple Inc. All Rights Reserved.

 
*/

#import <ServiceManagement/ServiceManagement.h>
#import <Security/Authorization.h>
#import "SMJobBlessAppController.h"
#include "SampleCommon.h"

@interface SMJobBlessAppController () {
    AuthorizationRef _authRef;
    xpc_connection_t _connection;
}

@property (nonatomic, assign)	IBOutlet NSTextField* textField;

- (IBAction)getVersion:(id)sender;
- (IBAction)doSecretSpyStuff:(id)sender;

- (BOOL)blessHelperWithLabel:(NSString *)label error:(NSError **)error;
- (int64_t)helperVersion;

- (void)openXPCConnection;
- (void)closeXPCConnection;

- (NSData *)authorizationData;

- (void)sendXPCRequest:(char *)request;
- (void)sendXPCRequest:(char *)request authorize:(BOOL)authorize;
- (void)sendXPCRequest:(char *)request authorize:(BOOL)authorize handler:(xpc_handler_t)handler;

- (xpc_object_t)sendSynchronousXPCRequest:(char *)request;
- (xpc_object_t)sendSynchronousXPCRequest:(char *)request authorize:(BOOL)authorize;

@end


@implementation SMJobBlessAppController

- (void)appendLog:(NSString *)log {
    self.textField.stringValue = [self.textField.stringValue stringByAppendingFormat:@"\n%@", log];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
	NSError *error = nil;
    
    [self openXPCConnection];
    
	if (self.helperVersion != SMJOBBLESSHELPER_VERSION) {
        [self closeXPCConnection];
        
        if (![self blessHelperWithLabel:@"com.apple.bsd.SMJobBlessHelper" error:&error]) {
            [self appendLog:[NSString stringWithFormat:@"Failed to bless helper. Error: %@", error]];
            return;
        }
        
        [self openXPCConnection];
    }
    
    self.textField.stringValue = @"Helper available.";
    
    [self sendXPCRequest:"Hi there, helper service."];
}

- (BOOL)blessHelperWithLabel:(NSString *)label error:(NSError **)error {
    if (_connection != NULL) {
        [self closeXPCConnection];
    }

	BOOL result = NO;

	AuthorizationItem authItem		= { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
	AuthorizationRights authRights	= { 1, &authItem };
	AuthorizationFlags flags		=	kAuthorizationFlagDefaults				| 
										kAuthorizationFlagInteractionAllowed	|
										kAuthorizationFlagPreAuthorize			|
										kAuthorizationFlagExtendRights;

	AuthorizationRef authRef = NULL;
	
	/* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
	OSStatus status = AuthorizationCreate(&authRights, kAuthorizationEmptyEnvironment, flags, &authRef);
	if (status != errAuthorizationSuccess) {
        [self appendLog:[NSString stringWithFormat:@"Failed to create AuthorizationRef. Error code: %ld", (long)status]];
	} else {
        result = SMJobRemove(kSMDomainSystemLaunchd, (CFStringRef)label, authRef, YES, (CFErrorRef *)error);
    }
    
    if (result) {
		/* This does all the work of verifying the helper tool against the application
		 * and vice-versa. Once verification has passed, the embedded launchd.plist
		 * is extracted and placed in /Library/LaunchDaemons and then loaded. The
		 * executable is placed in /Library/PrivilegedHelperTools.
		 */
		result = SMJobBless(kSMDomainSystemLaunchd, (CFStringRef)label, authRef, (CFErrorRef *)error);
	}
    
    AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);
	
	return result;
}

- (void)openXPCConnection {
    if (_connection != NULL) {
        [self closeXPCConnection];
    }
    
    _connection = xpc_connection_create_mach_service("com.apple.bsd.SMJobBlessHelper", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    
    if (!_connection) {
        [self appendLog:@"Failed to create XPC connection."];
        return;
    }
    
    xpc_connection_set_event_handler(_connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        
        if (type == XPC_TYPE_ERROR) {
            
            if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
                [self appendLog:@"XPC connection interupted."];
                
            } else if (event == XPC_ERROR_CONNECTION_INVALID) {
                [self appendLog:@"XPC connection invalid, releasing."];
                xpc_release(_connection);
                
            } else {
                [self appendLog:@"Unexpected XPC connection error."];
            }
            
        } else {
            [self appendLog:@"Unexpected XPC connection event."];
        }
    });
    
    xpc_connection_resume(_connection);
}

- (void)closeXPCConnection {
    if (_connection != NULL) {
        xpc_connection_suspend(_connection);
        xpc_connection_cancel(_connection);
        xpc_release(_connection);
        _connection = NULL;
    }
}

- (NSData *)authorizationData {
    NSData *authData = nil;
    
    AuthorizationItem item;
    
    item.name = "test_right";
    item.valueLength = 0;
    item.value = NULL;
    item.flags = 0;
    
    AuthorizationRights rights;
    
    rights.count = 1;
    rights.items = &item;
    
    OSStatus err = errAuthorizationSuccess;
    
    if (_authRef == NULL) {
        err = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &_authRef);
        
        if (err != errAuthorizationSuccess) {
            _authRef = NULL;
        }
    }
    
    if (err == errAuthorizationSuccess) {
        err = AuthorizationCopyRights(_authRef, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagDestroyRights, NULL);
    }
    
    AuthorizationExternalForm extForm;
    
    if (err == errAuthorizationSuccess) {
        err = AuthorizationMakeExternalForm(_authRef, &extForm);
    }

    if (err == errAuthorizationSuccess) {
        authData = [NSData dataWithBytes:&extForm length:sizeof(extForm)];
    }
    
    return authData;
}

- (void)destroyAuthorizationRights {
    AuthorizationFree(_authRef, kAuthorizationFlagDestroyRights);
    _authRef = NULL;
}

- (void)sendXPCRequest:(char *)request {
    [self sendXPCRequest:request authorize:NO];
}

- (void)sendXPCRequest:(char *)request authorize:(BOOL)authorize {
    [self sendXPCRequest:request authorize:authorize handler:^(xpc_object_t event) {
        const char* response = xpc_dictionary_get_string(event, "reply");
        [self appendLog:[NSString stringWithFormat:@"Received response: %s.", response]];
    }];
}

- (void)sendXPCRequest:(char *)request authorize:(BOOL)authorize handler:(xpc_handler_t)handler {
    if (_connection == NULL) {
        handler(NULL);
        return;
    }
    
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "request", request);
    
    if (authorize) {
        NSData *authData = self.authorizationData;
        xpc_dictionary_set_data(message, "authData", authData.bytes, authData.length);
    }
    
    [self appendLog:[NSString stringWithFormat:@"Sending request: %s", request]];
    
    xpc_connection_send_message_with_reply(_connection, message, dispatch_get_main_queue(), ^(xpc_object_t event) {
        if (authorize) {
            [self destroyAuthorizationRights];
        }
        
        handler(event);
    });
}

- (xpc_object_t)sendSynchronousXPCRequest:(char *)request {
    return [self sendSynchronousXPCRequest:request authorize:NO];
}

- (xpc_object_t)sendSynchronousXPCRequest:(char *)request authorize:(BOOL)authorize {
    if (_connection == NULL) {
        return NULL;
    }
    
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "request", request);
    
    if (authorize) {
        NSData *authData = self.authorizationData;
        xpc_dictionary_set_data(message, "authData", authData.bytes, authData.length);
    }
    
    [self appendLog:[NSString stringWithFormat:@"Sending request: %s", request]];
    
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(_connection, message);
    
    if (authorize) {
        [self destroyAuthorizationRights];
    }
    
    return reply;
}

- (int64_t)helperVersion {
    xpc_object_t event = [self sendSynchronousXPCRequest:"getVersion"];
    
    if (event == NULL) {
        return 0;
    }
    
    int64_t version = xpc_dictionary_get_int64(event, "version");
    
    xpc_release(event);
    
    return version;
}

- (IBAction)getVersion:(id)sender {
    [self appendLog:[NSString stringWithFormat:@"Version is %lld", self.helperVersion]];
}

- (IBAction)doSecretSpyStuff:(id)sender {
    xpc_object_t event = [self sendSynchronousXPCRequest:"secretSpyStuff" authorize:YES];
    
    if (event == NULL) {
        return;
    }
    
    [self appendLog:[NSString stringWithFormat:@"%s", xpc_dictionary_get_string(event, "reply")]];
}

@end
