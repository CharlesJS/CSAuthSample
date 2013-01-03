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
#include "SMJobBlessXPCLib.h"
#include "SampleCommon.h"

@interface SMJobBlessAppController ()

@property (nonatomic, assign)	IBOutlet NSTextField* textField;

- (IBAction)getVersion:(id)sender;
- (IBAction)doSecretSpyStuff:(id)sender;

- (BOOL)blessHelperWithLabel:(NSString *)label error:(NSError **)error;

- (void)requestHelperVersion:(void (^)(int64_t version, NSError *error))handler;

- (void)sendRequest:(NSDictionary *)request;
- (void)sendRequest:(NSDictionary *)request replyHandler:(void (^)(NSDictionary *response))replyHandler;
- (void)sendRequest:(NSDictionary *)request errorHandler:(void (^)(NSError *error))errorHandler replyHandler:(void (^)(NSDictionary *response))replyHandler;

@end


@implementation SMJobBlessAppController {
    AuthorizationRef _authRef;
}

- (void)appendLog:(NSString *)log {
    self.textField.stringValue = [self.textField.stringValue stringByAppendingFormat:@"\n%@", log];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    OSStatus err = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &_authRef);
    
    if (err != errAuthorizationSuccess) {
        [self appendLog:[NSString stringWithFormat:@"Failed to create AuthorizationRef. Error %ld", (long)err]];
        return;
    }
    
    SJBXSetDefaultRules(_authRef, kSampleCommandSet, (CFStringRef)[NSBundle mainBundle].bundleIdentifier, NULL);
    
    [self requestHelperVersion:^(int64_t version, NSError *error) {
        if (error != nil || version != SMJOBBLESSHELPER_VERSION) {
            NSError *blessError = nil;
            
            if (![self blessHelperWithLabel:@kSampleHelperID error:&blessError]) {
                [self appendLog:[NSString stringWithFormat:@"Failed to bless helper. Error: %@", blessError]];
                return;
            }
        }
    
        self.textField.stringValue = @"Helper available.";
    }];
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    if (_authRef != NULL) {
        AuthorizationFree(_authRef, kAuthorizationFlagDestroyRights);
        _authRef = NULL;
    }
}

- (BOOL)blessHelperWithLabel:(NSString *)label error:(NSError **)error {
	BOOL result = NO;

	AuthorizationItem authItem		= { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
	AuthorizationRights authRights	= { 1, &authItem };
	AuthorizationFlags flags		=	kAuthorizationFlagDefaults				| 
										kAuthorizationFlagInteractionAllowed	|
										kAuthorizationFlagPreAuthorize			|
										kAuthorizationFlagExtendRights;
	
	/* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
	OSStatus status = AuthorizationCreate(&authRights, kAuthorizationEmptyEnvironment, flags, &_authRef);
	if (status != errAuthorizationSuccess) {
        [self appendLog:[NSString stringWithFormat:@"Failed to create AuthorizationRef. Error code: %ld", (long)status]];
	} else {
        SMJobRemove(kSMDomainSystemLaunchd, (CFStringRef)label, _authRef, YES, NULL);
    
        /* This does all the work of verifying the helper tool against the application
		 * and vice-versa. Once verification has passed, the embedded launchd.plist
		 * is extracted and placed in /Library/LaunchDaemons and then loaded. The
		 * executable is placed in /Library/PrivilegedHelperTools.
		 */
		result = SMJobBless(kSMDomainSystemLaunchd, (CFStringRef)label, _authRef, (CFErrorRef *)error);
    }
	
	return result;
}

- (void)sendRequest:(NSDictionary *)request {
    void (^replyHandler)(NSDictionary *) = ^(NSDictionary *response) {
        NSString *reply = response[@"Reply"];
        
        [self appendLog:[NSString stringWithFormat:@"Received response: %@.", reply]];
    };
    
    [self sendRequest:request replyHandler:replyHandler];
}

- (void)sendRequest:(NSDictionary *)request replyHandler:(void (^)(NSDictionary *))replyHandler {
    void (^errorHandler)(NSError *) = ^(NSError *error) {
        [self appendLog:[NSString stringWithFormat:@"An error occurred when sending the request: %@", error]];
    };
    
    [self sendRequest:request errorHandler:errorHandler replyHandler:replyHandler];
}

- (void)sendRequest:(NSDictionary *)request errorHandler:(void (^)(NSError *))errorHandler replyHandler:(void (^)(NSDictionary *))replyHandler {
    void (^cfErrorHandler)(CFErrorRef) = ^(CFErrorRef errorRef) {
        errorHandler((NSError *)errorRef);
    };
    
    void (^cfReplyHandler)(CFDictionaryRef) = ^(CFDictionaryRef replyRef) {
        replyHandler((NSDictionary *)replyRef);
    };
    
    [self appendLog:[NSString stringWithFormat:@"Sending request: %@", request[@kSJBXCommandKey]]];
    
    SJBXExecuteRequestInHelperTool(_authRef, kSampleCommandSet, CFSTR(kSampleHelperID), (CFDictionaryRef)request, cfErrorHandler, cfReplyHandler);
}

- (void)requestHelperVersion:(void (^)(int64_t, NSError *))handler {
    NSDictionary *request = @{ @kSJBXCommandKey : @kSampleGetVersionCommand };
    
    void (^replyHandler)(NSDictionary *) = ^(NSDictionary *response) {
        NSNumber *version = response[@kSampleGetVersionResponse];
        
        handler(version.longLongValue, nil);
    };
    
    void (^errorHandler)(NSError *) = ^(NSError *error) {
        handler(-1, error);
    };
    
    [self sendRequest:request errorHandler:errorHandler replyHandler:replyHandler];
}

- (IBAction)getVersion:(id)sender {
    [self requestHelperVersion:^(int64_t version, NSError *error) {
        if (error == nil) {
            [self appendLog:[NSString stringWithFormat:@"Version is %lld", (long long)version]];
        } else {
            [self appendLog:[NSString stringWithFormat:@"Error getting version: %@", error]];
        }
    }];
}

- (IBAction)doSecretSpyStuff:(id)sender {
    NSDictionary *request = @{ @kSJBXCommandKey : @kSampleSecretSpyStuffCommand };
    
    [self sendRequest:request];
}

@end
