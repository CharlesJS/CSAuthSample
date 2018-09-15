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
        *error = CSASConvertOSStatus(err);
        return NO;
    }
    
    return YES;
}

#pragma mark * CSASBuiltInCommands

- (void)getEndpointWithAuthorizationData:(NSData *)authData endpoint:(void (^)(NSXPCListenerEndpoint * _Nullable, NSError * _Nullable))reply {
    NSError *error = nil;
    if (![self checkAuthorization:authData forCommand:_cmd error:&error]) {
        reply(nil, error);
        return;
    }
    
    reply(self.helperTool.listener.endpoint, nil);
}

- (void)getVersionWithReply:(void (^)(NSString * _Nullable, NSError * _Nullable))reply {
    NSString *vers = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
    
    if (vers != nil) {
        reply(vers, nil);
    } else {
        reply(nil, [[NSError alloc] initWithDomain:NSCocoaErrorDomain code:NSFileReadUnknownError userInfo:nil]);
    }
}

- (void)uninstallHelperToolWithAuthorizationData:(NSData *)authData reply:(void (^)(NSError * _Nullable))reply {
    NSFileManager *fm = [NSFileManager defaultManager];
    
    NSURL *helperURL = [NSURL fileURLWithPath:[NSProcessInfo processInfo].arguments[0]];

    if (helperURL == nil) {
        reply([[NSError alloc] initWithDomain:NSCocoaErrorDomain code:NSFileWriteUnknownError userInfo:nil]);
        return;
    }
    
    NSURL *libraryURL = [fm URLForDirectory:NSLibraryDirectory inDomain:NSLocalDomainMask appropriateForURL:nil create:NO error:NULL];
    
    NSURL *daemonsURL = [libraryURL URLByAppendingPathComponent:@"LaunchDaemons"];
    
    NSURL *serviceURL = [[daemonsURL URLByAppendingPathComponent:self.helperTool.helperID] URLByAppendingPathExtension:@"plist"];
    
    NSError *error = nil;
    
    if (![self checkAuthorization:authData forCommand:_cmd error:&error]) {
        reply(error);
        return;
    }
        
    if ([helperURL checkResourceIsReachableAndReturnError:NULL] &&
        ![fm removeItemAtURL:helperURL error:&error]) {
        reply(error);
        return;
    }
    
    if ([serviceURL checkResourceIsReachableAndReturnError:NULL] &&
        ![fm removeItemAtURL:serviceURL error:&error]) {
        reply(error);
        return;
    }
    
    reply(nil);
}

@end
