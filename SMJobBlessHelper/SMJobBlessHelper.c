/*
 
    File: SMJobBlessHelper.c
Abstract: A helper tool that doesn't do anything event remotely interesting.
See the ssd sample for how to use GCD and launchd to set up an on-demand
server via sockets.
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

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <syslog.h>
#include <xpc/xpc.h>
#include "SampleCommon.h"

CFMutableSetRef connections = NULL;

static OSStatus GetRootPrivileges(AuthorizationRef authRef) {
    AuthorizationItem item;
    
    item.name = "test_right";
    item.valueLength = 0;
    item.value = NULL;
    item.flags = 0;
    
    AuthorizationRights rights;
    
    rights.count = 1;
    rights.items = &item;

    return AuthorizationCopyRights(authRef, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagDestroyRights, NULL);
}

static void __XPC_Peer_Event_Handler(xpc_connection_t connection, xpc_object_t event) {
    syslog(LOG_NOTICE, "%ld: Received event in helper. Connection is %p", (long)getpid(), connection);
    
	xpc_type_t type = xpc_get_type(event);
    
	if (type == XPC_TYPE_ERROR) {
        syslog(LOG_NOTICE, "%ld: Some kind of error occurred with connection %p", (long)getpid(), connection);
        
		if (event == XPC_ERROR_CONNECTION_INVALID) {
			// The client process on the other end of the connection has either
			// crashed or cancelled the connection. After receiving this error,
			// the connection is in an invalid state, and you do not need to
			// call xpc_connection_cancel(). Just tear down any associated state
			// here.
            syslog(LOG_NOTICE, "%ld: invalid connection", (long)getpid());
            
            CFSetRemoveValue(connections, connection);
            
            if (CFSetGetCount(connections) == 0) {
                syslog(LOG_NOTICE, "%ld: no more connections", (long)getpid());
                //exit(0);
            }
		} else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
            syslog(LOG_NOTICE, "%ld: termination imminent", (long)getpid());
			// Handle per-connection termination cleanup.
		}
	} else if (type == XPC_TYPE_DICTIONARY) {
        const char *request = xpc_dictionary_get_string(event, "request");
        
        if (strcmp(request, "getVersion") == 0) {
            xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
            
            xpc_object_t reply = xpc_dictionary_create_reply(event);
            xpc_dictionary_set_int64(reply, "version", (int64_t)SMJOBBLESSHELPER_VERSION);
            xpc_connection_send_message(remote, reply);
            xpc_release(reply);
        } else if (strcmp(request, "secretSpyStuff") == 0) {
            size_t authDataLength = 0;
            const char *authData = xpc_dictionary_get_data(event, "authData", &authDataLength);
            AuthorizationExternalForm extForm;
            
            assert(authDataLength <= sizeof(extForm));
            
            memcpy(&extForm, authData, authDataLength);
            
            AuthorizationRef authRef = NULL;
            OSStatus err = AuthorizationCreateFromExternalForm(&extForm, &authRef);
            
            if (err != noErr) {
                err = GetRootPrivileges(authRef);
                AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);
            }
            
            const char *replyMessage;
            
            if (err == errAuthorizationSuccess) {
                replyMessage = "Hello 007";
            } else {
                syslog(LOG_NOTICE, "error %ld", (long)err);
                replyMessage = "I'd have to kill you";
            }
            
            xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
            
            xpc_object_t reply = xpc_dictionary_create_reply(event);
            xpc_dictionary_set_string(reply, "reply", replyMessage);
            xpc_connection_send_message(remote, reply);
            xpc_release(reply);
        } else {
            xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
            
            xpc_object_t reply = xpc_dictionary_create_reply(event);
            xpc_dictionary_set_string(reply, "reply", "Hi there, host application!");
            xpc_connection_send_message(remote, reply);
            xpc_release(reply);
        }
	}
}

static void __XPC_Connection_Handler(xpc_connection_t connection)  {
    syslog(LOG_NOTICE, "%ld: Configuring message event handler for helper. Connection is %p", (long)getpid(), connection);
    
    CFSetAddValue(connections, connection);
    
	xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
		__XPC_Peer_Event_Handler(connection, event);
	});
	
	xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    connections = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
    
    xpc_connection_t service = xpc_connection_create_mach_service("com.apple.bsd.SMJobBlessHelper",
                                                                  dispatch_get_main_queue(),
                                                                  XPC_CONNECTION_MACH_SERVICE_LISTENER);
    
    if (!service) {
        syslog(LOG_NOTICE, "Failed to create service.");
        exit(EXIT_FAILURE);
    }
    
    syslog(LOG_NOTICE, "%ld: Configuring connection event handler for helper. Service is %p", (long)getpid(), service);
    xpc_connection_set_event_handler(service, ^(xpc_object_t connection) {
        __XPC_Connection_Handler(connection);
    });
    
    xpc_connection_resume(service);
    
    dispatch_main();
    
    xpc_release(service);
    CFRelease(connections);
    
    return EXIT_SUCCESS;
}

