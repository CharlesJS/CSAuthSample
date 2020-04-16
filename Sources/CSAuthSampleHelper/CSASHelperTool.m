//
//  CSASHelperTool.m
//  Helper Library
//
//  Based on HelperTool.m from EvenBetterAuthorizationSample,
//  Copyright © 2013 Apple Computer.
//
//  Created by Charles Srstka on 6/25/18.
//

@import Foundation;
@import Darwin.POSIX.syslog;
@import ObjectiveC.runtime;
#import "CSASHelperTool.h"
#import "CSASHelperToolInternal.h"
#import "CSASHelperConnection.h"

NS_ASSUME_NONNULL_BEGIN

@interface CSASHelperTool() <NSXPCListenerDelegate>

@property (nonatomic, readonly) CSASCommandSet *commandSet;
@property (nonatomic, readonly) NSArray<NSString *> *requirements;
@property (nonatomic, readonly) Class connectionClass;
@property (nonatomic, readonly) NSXPCInterface *interface;

@property (nonatomic) NSUInteger connectionCount;

@end

@implementation CSASHelperTool

- (instancetype)initWithHelperID:(NSString *)helperID
                      commandSet:(CSASCommandSet *)commandSet
              senderRequirements:(nullable NSArray<NSString *> *)senderRequirements
                 connectionClass:(Class)connectionClass
                        protocol:(Protocol *)protocol {
    NSXPCInterface *interface = [NSXPCInterface interfaceWithProtocol:protocol];
    
    return [self initWithHelperID:helperID
                       commandSet:commandSet
               senderRequirements:senderRequirements
                  connectionClass:connectionClass
                        interface:interface];
}

- (instancetype)initWithHelperID:(NSString *)helperID
                      commandSet:(CSASCommandSet *)commandSet
              senderRequirements:(nullable NSArray<NSString *> *)_senderRequirements
                 connectionClass:(Class)connectionClass // must be CSASHelperConnection subclass
                       interface:(NSXPCInterface *)interface {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    NSArray<NSString *> *senderRequirements;
    if (_senderRequirements != nil) {
        senderRequirements = _senderRequirements;
    } else {
        senderRequirements = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"SMAuthorizedClients"];
    }
    
    [CSASHelperTool configureDefaultsForInterface:interface commandSet:commandSet];
    
    // Set up our XPC listener to handle requests on our Mach service.
    self->_listener = [[NSXPCListener alloc] initWithMachServiceName:helperID];
    self->_listener.delegate = self;
    self->_commandSet = commandSet;
    self->_requirements = [senderRequirements copy];
    self->_connectionClass = connectionClass;
    self->_interface = interface;
    self->_connectionCount = 0;
    self->_helperID = [helperID copy];
    
    return self;
}

+ (void)configureDefaultsForInterface:(NSXPCInterface *)interface commandSet:(CSASCommandSet *)commandSet {
    NSSet<Class> *data = [NSSet setWithObject:[NSData class]];
    NSSet<Class> *string = [NSSet setWithObject:[NSString class]];
    NSSet<Class> *endpoint = [NSSet setWithObject:[NSXPCListenerEndpoint class]];
    NSSet<Class> *error = [NSSet setWithObject:[NSError class]];
    
    SEL getEndpoint = @selector(getEndpointWithAuthorizationData:endpoint:);
    
    [interface setClasses:data forSelector:getEndpoint argumentIndex:0 ofReply:NO];
    [interface setClasses:endpoint forSelector:getEndpoint argumentIndex:0 ofReply:YES];
    [interface setClasses:error forSelector:getEndpoint argumentIndex:1 ofReply:YES];
    
    SEL getVersion = @selector(getVersionWithReply:);
    
    [interface setClasses:string forSelector:getVersion argumentIndex:0 ofReply:YES];
    [interface setClasses:error forSelector:getVersion argumentIndex:1 ofReply:YES];
    
    SEL uninstall = @selector(uninstallHelperToolWithAuthorizationData:reply:);
    
    [interface setClasses:data forSelector:uninstall argumentIndex:0 ofReply:NO];
    [interface setClasses:error forSelector:uninstall argumentIndex:0 ofReply:YES];
    
    for (CSASAuthorizationRight *eachRight in commandSet.authorizationRights) {
        // getVersion is allowed not to have an auth parameter
        if (sel_isEqual(eachRight.selector, getVersion)) {
            continue;
        }
        
        if (![[interface classesForSelector:eachRight.selector argumentIndex:0 ofReply:NO] isEqualToSet:data]) {
            NSString *name = @"CSAuthSampleMissingAuthorizationData";
            NSString *reason = @"All privileged operations must include an authorizationData parameter.";
            
            NSException *exception = [[NSException alloc] initWithName:name reason:reason userInfo:nil];
            
            [exception raise];
        }
    }
}

- (void)run {
    [self.listener resume];
    
    [[NSRunLoop currentRunLoop] run];
    
    // Should never get here. Crash if we do.
    exit(EXIT_FAILURE);
}

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)conn {
    assert(listener == self.listener);
    assert(conn != nil);
    
    if (![self shouldApproveConnection:conn]) {
        return NO;
    }
    
    conn.exportedInterface = self.interface;
    conn.exportedObject = [(CSASHelperConnection *)[self.connectionClass alloc] initWithConnection:conn helperTool:self commandSet:self.commandSet];
    
    // Keep track of how many connections we have open. If the number reaches zero, exit the process.
    // This will prevent the helper tool from sticking around long after we're done with it.
    self.connectionCount++;
    conn.invalidationHandler = ^{
        self.connectionCount--;
        
        if (self.connectionCount == 0) {
            exit(0);
        }
    };
    
    [conn resume];
    
    return YES;
}

- (BOOL)shouldApproveConnection:(NSXPCConnection *)connection {
    for (NSString *eachRequirement in self.requirements) {
        if ([self checkCodeSigningForConnection:connection requirement:eachRequirement error:NULL]) {
            return YES;
        }
    }
    
    return NO;
}

- (BOOL)checkCodeSigningForConnection:(NSXPCConnection *)connection
                          requirement:(NSString *)req
                                error:(__autoreleasing NSError * _Nullable * _Nullable)error {
    // Check the code signing requirement for the command.
    
    SecCodeRef secCode = NULL;
    SecRequirementRef secRequirement = NULL;
    
    @try {
        pid_t pid = connection.processIdentifier;
        NSDictionary *codeAttrs = @{ (__bridge NSString *)kSecGuestAttributePid: @(pid) };
    
        OSStatus err = SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)codeAttrs, kSecCSDefaultFlags, &secCode);
        
        if (err != errSecSuccess) {
            if (error) *error = CSASConvertOSStatus(err);
            return NO;
        }
        
        err = SecRequirementCreateWithString((__bridge CFStringRef)req, kSecCSDefaultFlags, &secRequirement);
    
        if (err != errSecSuccess) {
            if (error) *error = CSASConvertOSStatus(err);
            return NO;
        }
    
        err = SecCodeCheckValidity(secCode, kSecCSDefaultFlags, secRequirement);
        
        if (err == errSecSuccess) {
            return YES;
        } else {
            if (error) *error = CSASConvertOSStatus(err);
            return NO;
        }
    }
    @finally {
        if (secCode != NULL) {
            CFRelease(secCode);
        }
    
        if (secRequirement != NULL) {
            CFRelease(secRequirement);
        }
    }
}

- (void)log:(NSString *)format, ... {
    va_list list;
    va_start(list, format);
    
    [self logWithPriority:LOG_NOTICE format:format arguments:list];
    
    va_end(list);
}

- (void)logWithPriority:(int)priority format:(NSString *)format, ... {
    va_list list;
    va_start(list, format);
    
    [self logWithPriority:priority format:format arguments:list];
    
    va_end(list);
}

- (void)logWithPriority:(int)priority format:(NSString *)format arguments:(va_list)args {
    NSString *string = [[NSString alloc] initWithFormat:format arguments:args];
    
    syslog(LOG_NOTICE, "%s", string.UTF8String);
}

@end

NS_ASSUME_NONNULL_END
