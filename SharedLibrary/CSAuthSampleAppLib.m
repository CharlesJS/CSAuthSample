// CSAuthSampleAppLib.h
// Copyright Charles Srstka, 2013-2015.
// Based on BetterAuthorizationSampleLib.c by Apple Computer.

#import "CSAuthSampleAppLib.h"
#include <ServiceManagement/ServiceManagement.h>
#include <Security/Authorization.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(objc_arc)
#define USING_ARC           1
#endif

#if USING_ARC
#define RELEASE(x)
#define AUTORELEASE(x)      (x)
#define BRIDGE(type, var)   ((__bridge type)(var))
#define BRIDGING_RELEASE(x) CFBridgingRelease(x)
#define SUPER_DEALLOC
#else
#define RELEASE(x)          [(x) release]
#define AUTORELEASE(x)      [(x) autorelease]
#define BRIDGE(type, var)   ((type)(var))
#define BRIDGING_RELEASE(x) [(id)(x) autorelease]
#define SUPER_DEALLOC       [super dealloc]
#endif

#if USING_ARC && OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#define RETAIN_XPC(x)       (x)
#define RELEASE_XPC(x)
#else
#define RETAIN_XPC(x)       xpc_retain(x)
#define RELEASE_XPC(x)      xpc_release(x)
#endif

@interface CSASRequestSender ()

@property (copy) NSString *helperID;

@end

@interface CSASHelperConnection ()

@property (readwrite) BOOL isValid;

@property (copy) NSError *connectionError;

- (instancetype)initWithXPCConnection:(xpc_connection_t)conn;

@end

static BOOL CSASConvertErrnoToCocoaError(int err, NSInteger *cocoaError) {
    BOOL converted = YES;
    
    switch(err) {
        case ECANCELED:
            *cocoaError = NSUserCancelledError;
            break;
        case ENOENT:
            *cocoaError = NSFileNoSuchFileError;
            break;
        case EFBIG:
            *cocoaError = NSFileReadTooLargeError;
            break;
        case EEXIST:
            *cocoaError = NSFileWriteFileExistsError;
            break;
        case ENOSPC:
            *cocoaError = NSFileWriteOutOfSpaceError;
            break;
        case EROFS:
            *cocoaError = NSFileWriteVolumeReadOnlyError;
            break;
        default:
            converted = NO;
    }
    
    return converted;
}

static BOOL CSASConvertOSStatusToCocoaError(OSStatus err, NSInteger *cocoaError) {
    BOOL converted = YES;
    
    if (err >= errSecErrnoBase && err <= errSecErrnoLimit) {
        converted = CSASConvertErrnoToCocoaError(err - errSecErrnoBase, cocoaError);
    } else switch(err) {
        case userCanceledErr:
        case errAuthorizationCanceled:
        case errAEWaitCanceled:
        case kernelCanceledErr:
        case kOTCanceledErr:
        case kECANCELErr:
        case errIACanceled:
        case kRAConnectionCanceled:
        case kTXNUserCanceledOperationErr:
        case kFBCindexingCanceled:
        case kFBCaccessCanceled:
        case kFBCsummarizationCanceled:
            *cocoaError = NSUserCancelledError;
            break;
        case fnfErr:
            *cocoaError = NSFileNoSuchFileError;
            break;
        case fileBoundsErr:
        case fsDataTooBigErr:
            *cocoaError = NSFileReadTooLargeError;
            break;
        case dupFNErr:
            *cocoaError = NSFileWriteFileExistsError;
            break;
        case dskFulErr:
        case errFSNotEnoughSpaceForOperation:
            *cocoaError = NSFileWriteOutOfSpaceError;
            break;
        case vLckdErr:
            *cocoaError = NSFileWriteVolumeReadOnlyError;
            break;
        default:
            converted = NO;
    }
    
    return converted;
}

static NSError *CSASConvertedError(NSError *error) {
    // Cocoa tends to do a nicer job presenting Cocoa errors than POSIX or OSStatus ones, particularly with NSUserCancelledError,
    // in which case -presentError: will skip showing the error altogether. For certain other error types, using the Cocoa domain
    // will provide a little more information, including, sometimes, the filename for which the operation failed.
    // Therefore, convert errors to NSCocoaErrorDomain when possible.
    
    NSInteger cocoaError = 0;
    BOOL converted = NO;
    
    if ([error.domain isEqualToString:NSPOSIXErrorDomain]) {
        converted = CSASConvertErrnoToCocoaError((int)error.code, &cocoaError);
    } else if ([error.domain isEqualToString:NSOSStatusErrorDomain]) {
        converted = CSASConvertOSStatusToCocoaError((OSStatus)error.code, &cocoaError);
    }
    
    if (converted) {
        NSMutableDictionary<NSString *, id> *userInfo = error.userInfo.mutableCopy;
        
        userInfo[NSUnderlyingErrorKey] = error;
        
        // Use the built-in error messages instead
        if (userInfo[NSLocalizedFailureReasonErrorKey] != nil) {
            [userInfo removeObjectForKey:NSLocalizedFailureReasonErrorKey];
        }
        
        error = [[NSError alloc] initWithDomain:NSCocoaErrorDomain code:cocoaError userInfo:userInfo];
    }
    
    return error;
}

static NSError *CSASErrorFromXPCEvent(xpc_object_t event) {
    xpc_type_t type = xpc_get_type(event);
    NSError *error = nil;
    
    if (type == XPC_TYPE_ERROR) {
        if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
            error = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorConnectionInterrupted userInfo:nil];
        } else if (event == XPC_ERROR_CONNECTION_INVALID) {
            error = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorConnectionInvalid userInfo:nil];
        } else {
            error = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorUnexpectedConnection userInfo:nil];
        }
    }
    
    return error;
}

static NSArray<NSFileHandle *> *CSASFileHandlesFromXPCReply(xpc_object_t reply) {
    NSMutableArray<NSFileHandle *> *handleArray = [NSMutableArray array];
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
            
            [handleArray addObject:AUTORELEASE([[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES])];
        }
    }
    
    return handleArray;
}

static NSDictionary<NSString *, id> *CSASHandleXPCReply(xpc_object_t reply, NSArray<NSFileHandle *> **fileHandlesPtr, NSError **errorPtr) {
    NSDictionary<NSString *, id> *response = NULL;
    NSArray<NSFileHandle *> *fileHandles = nil;
    bool success = true;
    NSError *error = NULL;
    
    if (success) {
        response = BRIDGING_RELEASE(CSASCreateCFTypeFromXPCMessage(xpc_dictionary_get_value(reply, kCSASRequestKey)));
        
        if (response == nil) {
            success = false;
            error = BRIDGING_RELEASE(CSASCreateCFTypeFromXPCMessage(xpc_dictionary_get_value(reply, kCSASErrorKey)));
            
            if (error == nil) {
                error = BRIDGING_RELEASE(CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL));
            }
        }
    }
    
    if (success) {
        fileHandles = CSASFileHandlesFromXPCReply(reply);
    }
    
    if (success) {
        if (fileHandlesPtr != NULL) *fileHandlesPtr = fileHandles;
    } else {
        if (errorPtr != NULL) *errorPtr = CSASConvertedError(error);
        response = nil;
    }
    
    return response;
}

@interface CSASRequestSender ()

@property (nonatomic, copy) NSDictionary<NSString *, NSDictionary<NSString *, id> *> *commandSet;

@end

@implementation CSASRequestSender {
    AuthorizationRef _authRef;
}

- (instancetype)initWithCommandSet:(NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)commandSet helperID:(NSString *)helperID error:(NSError *__autoreleasing *)error {
    self = [super init];
    
    if (self == nil) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadUnknownError userInfo:nil];
        return nil;
    }
    
    OSStatus err = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &_authRef);
    
    if (err != errSecSuccess) {
        if (error) *error = CSASConvertedError(BRIDGING_RELEASE(CSASCreateCFErrorFromOSStatus(err, NULL)));
        RELEASE(self);
        return nil;
    }
    
    if (_authRef == NULL || helperID == nil || commandSet == NULL || commandSet.count == 0) { // there must be at least one command
        if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
        RELEASE(self);
        return nil;
    }
    
    _commandSet = [commandSet copy];
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
        _authRef = NULL;
    }
}

- (BOOL)blessHelperToolAndReturnError:(NSError *__autoreleasing *)error {
	BOOL success = NO;
    
	AuthorizationItem authItem		= { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
	AuthorizationRights authRights	= { 1, &authItem };
	AuthorizationFlags flags		= (kAuthorizationFlagDefaults             |
                                       kAuthorizationFlagInteractionAllowed	  |
                                       kAuthorizationFlagPreAuthorize         |
                                       kAuthorizationFlagExtendRights
                                       );
	
	/* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
    OSStatus status = AuthorizationCopyRights(_authRef, &authRights, kAuthorizationEmptyEnvironment, flags, NULL);
	if (status != errAuthorizationSuccess) {
        if (error) *error = CSASConvertedError(BRIDGING_RELEASE(CSASCreateCFErrorFromOSStatus(status, NULL)));
        success = NO;
	} else {
        CFErrorRef smError = NULL;
        
        [self syncRemoveHelperTool:error];
        
        /* This does all the work of verifying the helper tool against the application
         * and vice-versa. Once verification has passed, the embedded launchd.plist
         * is extracted and placed in /Library/LaunchDaemons and then loaded. The
         * executable is placed in /Library/PrivilegedHelperTools.
         */
        success = SMJobBless(kSMDomainSystemLaunchd, BRIDGE(CFStringRef, self.helperID), _authRef, &smError);
        
        if (!success) {
            if (error != NULL) {
                *error = CSASConvertedError(BRIDGING_RELEASE(smError));
            } else if (smError != NULL) {
                CFRelease(smError);
            }
        }
    }

	return success;
}

- (void)removeHelperTool:(void (^)(NSError *))handler {
    NSString *helperID = self.helperID;
    AuthorizationRef authRef = _authRef;
    
    [self executeCommandInHelperTool:@kCSASRemoveHelperCommand userInfo:nil responseHandler:^(__unused NSDictionary<NSString *, id> *response, __unused NSArray<NSFileHandle *> *handles, __unused CSASHelperConnection *persistentConnection, NSError *errorOrNil) {
        CFErrorRef smError = NULL;
        if (!SMJobRemove(kSMDomainSystemLaunchd, BRIDGE(CFStringRef, helperID), authRef, YES, &smError)) {
            errorOrNil = CFBridgingRelease(smError);
        }
        
        if (handler == nil) {
            return;
        }
        
        handler(errorOrNil);
    }];
}

- (BOOL)syncRemoveHelperTool:(NSError * __autoreleasing *)error {
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSError *outError;
    
    [self removeHelperTool:^(NSError *errorOrNil) {
        outError = errorOrNil;
        
        dispatch_semaphore_signal(semaphore);
    }];
    
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    
    if (outError != nil) {
        if (error) *error = outError;
        return NO;
    }
    
    return YES;
}

- (void)requestHelperVersion:(void (^)(NSString *, NSError *))handler {
    [self executeCommandInHelperTool:@kCSASGetVersionCommand userInfo:nil responseHandler:^(NSDictionary<NSString *, id> *response, __unused NSArray<NSFileHandle *> *fileHandles, __unused CSASHelperConnection *persistentConnection, NSError *errorOrNil) {
        if (handler == nil) {
            return;
        }
        
        if (errorOrNil != nil) {
            handler(nil, errorOrNil);
            return;
        }
        
        NSString *version = response[@kCSASGetVersionResponse];
            
        if (version == nil) {
            handler(nil, [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileReadUnknownError userInfo:nil]);
            return;
        }
        
        handler(version, nil);
    }];
}

- (void)executeCommandInHelperTool:(NSString *)commandName userInfo:(NSDictionary<NSString *, id> *)userInfo responseHandler:(CSASResponseHandler)responseHandler {
    bool                        success = true;
	AuthorizationExternalForm	extAuth;
    xpc_connection_t            connection = NULL;
    xpc_object_t 				message = NULL;

    NSDictionary<NSString *, id> *              command;
    
    CFErrorRef                  error = NULL;
    __block NSError *           connectionError = nil;
	
	// Pre-conditions
	
	assert(commandName != nil);
    
	// For debugging.
    
    assert([commandName isKindOfClass:[NSString class]]);
    assert(userInfo == nil || [userInfo isKindOfClass:[NSDictionary class]]);
    
    // Look up the command and preauthorize.  This has the nice side effect that
    // the authentication dialog comes up, in the typical case, here, rather than
    // in the helper tool.  This is good because the helper tool is global /and/
    // single threaded, so if it's waiting for an authentication dialog for user A
    // it can't handle requests from user B.
    
    command = BRIDGING_RELEASE(CSASCreateBuiltInCommandSet())[commandName];
    
    if (command == nil) {
        command = self.commandSet[commandName];
    }
    
    if (command == nil) {
        error = CSASCreateCFErrorFromErrno(EINVAL, NULL);
        success = false;
    }
    
    if (success) {
        NSString *rightName = command[BRIDGE(NSString *, kCSASCommandSpecRightNameKey)];
        
        if (rightName != NULL) {
            AuthorizationItem   item   = { (const char * _Nonnull)rightName.UTF8String, 0, NULL, 0 };
            AuthorizationRights rights = { 1, &item };
            
            OSStatus authErr = AuthorizationCopyRights(_authRef, &rights, kAuthorizationEmptyEnvironment, kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed | kAuthorizationFlagPreAuthorize, NULL);
            
            if (authErr != errSecSuccess) {
                success = false;
                error = CSASCreateCFErrorFromOSStatus(authErr, NULL);
            }
        }
    }
    
    // Open the XPC connection.
        
	if (success) {
		connection = xpc_connection_create_mach_service(self.helperID.fileSystemRepresentation, NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
		if (connection == NULL) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
		}
	}
    
    // Attempt to connect.
    
    if (success) {
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            xpc_type_t eventType = xpc_get_type(event);
            
            if (eventType == XPC_TYPE_ERROR) {
                if (connectionError == nil) {
                    connectionError = CSASErrorFromXPCEvent(event);
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
            error = CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL);
        }
    }
	
    // Send the flattened AuthorizationRef to the tool.
    
    if (success) {
        OSStatus authErr = AuthorizationMakeExternalForm(_authRef, &extAuth);
        
        if (authErr != errSecSuccess) {
            success = false;
            error = CSASCreateCFErrorFromOSStatus(authErr, NULL);
        }
    }
    
	if (success) {
        xpc_dictionary_set_data(message, kCSASAuthorizationRefKey, &extAuth, sizeof(extAuth));
	}
	
    // Write the request.
    
    if (success) {
        xpc_object_t xpcName = CSASCreateXPCMessageFromCFType(BRIDGE(CFStringRef, commandName));
        
        xpc_dictionary_set_value(message, kCSASCommandKey, xpcName);
        
        RELEASE_XPC(xpcName);
    }
    
	if (success && (userInfo != nil)) {
		xpc_object_t xpcRequest = CSASCreateXPCMessageFromCFType(BRIDGE(CFDictionaryRef, userInfo));
        
        xpc_dictionary_set_value(message, kCSASRequestKey, xpcRequest);
        
        RELEASE_XPC(xpcRequest);
	}
	
    // Send request.
    
    if (success) {
        xpc_connection_send_message_with_reply(connection, message, DISPATCH_TARGET_QUEUE_DEFAULT, ^(xpc_object_t reply) {
            NSDictionary<NSString *, id> *response = nil;
            NSArray<NSFileHandle *> *fileHandles = nil;
            CSASHelperConnection *helperConnection = nil;
            bool replySuccess = true;
            NSError *replyError = nil;
            
            if (connectionError != nil) {
                replyError = connectionError;
                replySuccess = false;
            }
            
            if (replySuccess) {
                response = CSASHandleXPCReply(reply, &fileHandles, &replyError);
                
                if (response == nil) {
                    replySuccess = false;
                }
            }
            
            if (replySuccess && xpc_dictionary_get_bool(reply, kCSASCanAcceptFurtherInputKey)) {
                helperConnection = AUTORELEASE([[CSASHelperConnection alloc] initWithXPCConnection:connection]);
            }
            
            void (^completionHandler)() = ^{
                if (replySuccess) {
                    responseHandler(response, fileHandles, helperConnection, nil);
                } else {
                    responseHandler(@{}, @[], nil, CSASConvertedError(replyError));
                }
            };
            
            if (self.operationQueue != nil) {
                [self.operationQueue addOperationWithBlock:completionHandler];
            } else {
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    completionHandler();
                });
            }
            
            RELEASE_XPC(message);
            RELEASE_XPC(connection);
        });
    }
    
    // If something failed, let the user know.
    
    if (!success) {
        if (responseHandler != nil) responseHandler(@{}, @[], nil, CSASConvertedError(BRIDGE(NSError *, error)));
        
        if (error != NULL) {
            CFRelease(error);
        }
        
        if (connection != NULL) {
            RELEASE_XPC(connection);
        }
        
        if (message != NULL) {
            RELEASE_XPC(message);
        }
    }
}

@end

@implementation CSASHelperConnection {
    xpc_connection_t _connection;
}

- (instancetype)initWithXPCConnection:(xpc_connection_t)conn {
    self = [super init];
    
    if (self == nil) {
        return nil;
    }
    
    _connection = RETAIN_XPC(conn);
    
    self.isValid = YES;
    
    xpc_connection_set_event_handler(_connection, ^(xpc_object_t event) {
        xpc_type_t eventType = xpc_get_type(event);
        
        if (eventType == XPC_TYPE_ERROR) {
            if (self.connectionError == nil) {
                self.connectionError = CSASErrorFromXPCEvent(event);
            }
            
            if (event == XPC_ERROR_CONNECTION_INVALID || XPC_ERROR_CONNECTION_INTERRUPTED) {
                [self closeConnection];
            }
        } else {
            if (self.connectionError == nil) {
                self.connectionError = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorUnexpectedEvent userInfo:nil];
            }
        }
    });
    
    return self;
}

- (void)dealloc {
    if (_connection != NULL) {
        RELEASE_XPC(_connection);
        _connection = NULL;
    }
    
    RELEASE(_operationQueue);
    RELEASE(_connectionError);
    
    SUPER_DEALLOC;
}

- (void)sendMessage:(NSDictionary<NSString *, id> *)messageDict responseHandler:(CSASResponseHandler)responseHandler {
    xpc_object_t message = nil;
    NSError *error = nil;
    bool success = true;
    
    self.connectionError = nil;
    
    if (!self.isValid) {
        error = [NSError errorWithDomain:BRIDGE(NSString *, kCSASErrorDomain) code:kCSASErrorConnectionInvalid userInfo:nil];
        success = false;
    }
    
    if (success) {
        message = xpc_dictionary_create(NULL, NULL, 0);
        
        if (message == NULL) {
            error = BRIDGING_RELEASE(CSASCreateCFErrorFromOSStatus(coreFoundationUnknownErr, NULL));
            success = false;
        }
    }
    
    if (success) {
        xpc_object_t xpcMessageDict = CSASCreateXPCMessageFromCFType(BRIDGE(CFDictionaryRef, messageDict));
        
        xpc_dictionary_set_value(message, kCSASRequestKey, xpcMessageDict);
        
        RELEASE_XPC(xpcMessageDict);
    }
    
    if (success) {
        xpc_connection_send_message_with_reply(_connection, message, dispatch_get_main_queue(), ^(xpc_object_t reply) {
            if (self.connectionError != nil) {
                responseHandler(@{}, @[], nil, self.connectionError);
            } else {
                NSArray<NSFileHandle *> *fileHandles = nil;
                NSError *replyError = nil;
                NSDictionary<NSString *, id> *response = CSASHandleXPCReply(reply, &fileHandles, &replyError);
                
                if (response == nil) {
                    responseHandler(@{}, @[], nil, replyError);
                } else {
                    responseHandler(response, fileHandles, nil, nil);
                }
            }
        });
    }
    
    if (!success) {
        responseHandler(@{}, @[], nil, error);
    }
    
    if (message != NULL) {
        RELEASE_XPC(message);
    }
}

- (void)closeConnection {
    @synchronized(self) {
        if (_connection != NULL) {
            // Set a blank event handler to prevent it from getting called while we are closing the connection.
            // Specifically, cancelling the connection will cause the XPC_ERROR_CONNECTION_INVALID event,
            // which then causes this method to be called again.
            xpc_connection_set_event_handler(_connection, ^(xpc_object_t event) {});
            xpc_connection_cancel(_connection);
            RELEASE_XPC(_connection);
            _connection = NULL;
            
            dispatch_async(dispatch_get_main_queue(), ^{
                self.isValid = NO;
            });
        }
    }
}

@end
