//
//  CSASHelperConnection.m
//  ObjC Helper Tool
//
//  Created by Charles Srstka on 7/1/18.
//

@import Foundation;
@import CSASHelperTool;
@import CSASHelperToolInternal;

@interface CSASHelperConnection ()

@property (nonatomic, readonly, weak) CSASHelperTool *helperTool;

@end

@implementation CSASHelperConnection

- (instancetype)initWithConnection:(NSXPCConnection *)connection
                        helperTool:(CSASHelperTool *)helperTool
                        commandSet:(CSASCommandSet *)commandSet {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    self->_connection = connection;
    self->_helperTool = helperTool;
    self->_commandSet = commandSet;
    
    return self;
}

- (BOOL)checkAuthorization:(NSData *)authData forCommand:(SEL)command error:(NSError *__autoreleasing  _Nullable *)error {
    // First check that authData looks reasonable.
    if ((authData == nil) || (authData.length != sizeof(AuthorizationExternalForm))) {
        *error = [[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
        return NO;
    }
    
    // Create an authorization ref from that the external form data contained within.
    AuthorizationRef authRef = NULL;
    OSStatus err = AuthorizationCreateFromExternalForm(authData.bytes, &authRef);
    
    if (err != errAuthorizationSuccess) {
        *error = CSASConvertOSStatus(err);
        return NO;
    }
    
    @try {
        // Call our authorization method.
        return [self _checkAuthorization:authRef forCommand:command error:error];
    }
    @finally {
        OSStatus junk = AuthorizationFree(authRef, 0);
        assert(junk == errAuthorizationSuccess);
    }
}

- (BOOL)_checkAuthorization:(AuthorizationRef)auth forCommand:(SEL)command error:(__autoreleasing NSError * _Nullable *)error {
    CSASAuthorizationRight *authRight = [self.commandSet authorizationRightForCommand:command];
    
    if (authRight == nil) {
        *error = [[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
        return NO;
    }
    
    // Authorize the right associated with the command.
    
    AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
    AuthorizationRights rights   = { 1, &oneRight };
    
    oneRight.name = (const char * _Nonnull)authRight.name.UTF8String;
    assert(oneRight.name != NULL);
    
    AuthorizationFlags flags = kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed;
    OSStatus err = AuthorizationCopyRights(auth, &rights, NULL, flags, NULL);
    
    if (err != errAuthorizationSuccess) {
        *error = [[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:err userInfo:nil];
        return NO;
    }
    
    return YES;
}

#pragma mark * CSASBuiltInCommands

// IMPORTANT: NSXPCConnection can call these methods on any thread.  It turns out that our
// implementation of these methods is thread safe but if that's not the case for your code
// you have to implement your own protection (for example, having your own serial queue and
// dispatching over to it).

- (void)getEndpointWithAuthorizationData:(NSData *)authData endpoint:(void (^)(NSXPCListenerEndpoint * _Nullable, NSError * _Nullable))reply {
    // Part of CSASBuiltInCommands.  Not used by the standard app (it's part of the sandboxed
    // XPC service support).  Called by the XPC service to get an endpoint for our listener.  It then
    // passes this endpoint to the app so that the sandboxed app can talk us directly.
    
    NSError *error = nil;
    if (![self checkAuthorization:authData forCommand:_cmd error:&error]) {
        reply(nil, error);
        return;
    }
    
    reply(self.helperTool.listener.endpoint, nil);
}

- (void)getVersionWithReply:(void (^)(NSString * _Nullable, NSError * _Nullable))reply {
    // Part of CSASBuiltInCommands. Returns the version number of the tool.
    
    reply([[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"], nil);
}

- (void)uninstallHelperToolWithAuthorizationData:(NSData *)authData reply:(void (^)(NSError * _Nullable))reply {
    // Part of CSASBuiltInCommands. Uninstalls the helper tool.
    
    NSURL *helperURL = [NSURL fileURLWithPath:[NSProcessInfo processInfo].arguments[0]];
    NSError *error = nil;
    
    if ([self checkAuthorization:authData forCommand:_cmd error:&error]) {
        if (helperURL == nil) {
            error = [[NSError alloc] initWithDomain:NSCocoaErrorDomain code:NSFileWriteUnknownError userInfo:nil];
        } else if ([helperURL checkResourceIsReachableAndReturnError:&error]) {
            if ([[NSFileManager defaultManager] removeItemAtURL:helperURL error:&error]) {
                error = nil;
            }
        }
    }
    
    reply(error);
}

@end
