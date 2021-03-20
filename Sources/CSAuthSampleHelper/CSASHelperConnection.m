//
//  CSASHelperConnection.m
//  Helper Tool
//
//  Created by Charles Srstka on 7/1/18.
//

@import Foundation;
#import "CSASHelperConnection.h"
#import "CSASHelperConnectionInternal.h"
#import "CSASHelperToolInternal.h"

@interface CSASHelperConnection ()

@property (nonatomic, readonly, weak) CSASHelperTool *helperTool;

@end

static NSString * const currentCommandKey = @"com.charlessoft.CSAuthSample.currentCommand";

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

- (SEL)currentCommand {
    NSString *cmdName = [NSThread currentThread].threadDictionary[currentCommandKey];
    
    return (cmdName == nil) ? nil : NSSelectorFromString(cmdName);
}

- (void)setCurrentCommand:(SEL)currentCommand {
    [NSThread currentThread].threadDictionary[currentCommandKey] = NSStringFromSelector(currentCommand);
}

- (nullable NSError *)checkAuthorization:(NSData *)authData {
    // First check that authData looks reasonable.
    if ((authData == nil) || (authData.length != sizeof(AuthorizationExternalForm))) {
        return [[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
    }
    
    // Create an authorization ref from that the external form data contained within.
    AuthorizationRef authRef = NULL;
    OSStatus err = AuthorizationCreateFromExternalForm(authData.bytes, &authRef);
    
    if (err != errAuthorizationSuccess) {
        return CSASConvertOSStatus(err);
    }
    
    @try {
        // Call our authorization method.
        return [self _checkAuthorization:authRef forCommand:self.currentCommand];
    }
    @finally {
        OSStatus junk = AuthorizationFree(authRef, 0);
        assert(junk == errAuthorizationSuccess);
    }
}

- (nullable NSError *)_checkAuthorization:(AuthorizationRef)auth forCommand:(SEL)command {
    CSASAuthorizationRight *authRight = [self.commandSet authorizationRightForCommand:command];
    
    if (authRight == nil) {
        return [[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:EINVAL userInfo:nil];
    }
    
    // Authorize the right associated with the command.
    
    AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
    AuthorizationRights rights   = { 1, &oneRight };
    
    oneRight.name = (const char * _Nonnull)authRight.name.UTF8String;
    assert(oneRight.name != NULL);
    
    AuthorizationFlags flags = kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed;
    OSStatus err = AuthorizationCopyRights(auth, &rights, NULL, flags, NULL);
    
    if (err != errAuthorizationSuccess) {
        return CSASConvertOSStatus(err);
    }
    
    return nil;
}

#pragma mark * CSASBuiltInCommands

- (void)getEndpointWithAuthorizationData:(NSData *)authData endpoint:(void (^)(NSXPCListenerEndpoint * _Nullable, NSError * _Nullable))reply {
    NSError *error = [self checkAuthorization:authData];
    if (error != nil) {
        reply(nil, error);
        return;
    }
    
    reply(self.helperTool.listener.endpoint, nil);
}

- (void)getVersionWithReply:(void (^)(NSString * _Nullable, NSError * _Nullable))reply {
    NSString *vers = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
    
    if (vers != nil) {
        reply([[NSString alloc] initWithFormat:@"%@", vers], nil);
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
    
    NSError *error = [self checkAuthorization:authData];
    
    if (error != nil) {
        reply(error);
        return;
    }
        
    if ([helperURL checkResourceIsReachableAndReturnError:NULL] && ![fm removeItemAtURL:helperURL error:&error]) {
        reply(error);
        return;
    }
    
    if ([serviceURL checkResourceIsReachableAndReturnError:NULL] && ![fm removeItemAtURL:serviceURL error:&error]) {
        reply(error);
        return;
    }
    
    reply(nil);
}

@end
