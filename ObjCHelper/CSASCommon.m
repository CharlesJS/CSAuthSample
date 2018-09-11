//
//  CSASCommon.m
//  ObjC Helper Library
//
//  Based on Common.m from EvenBetterAuthorizationSample,
//  Copyright © 2013 Apple Computer.
//
//  Created by Charles Srstka on 6/25/18.
//

@import Foundation;
@import CSASCommon;
@import Darwin.POSIX.syslog;

NS_ASSUME_NONNULL_BEGIN

@interface CSASCommandSet ()

@property (nonatomic, copy) NSDictionary<NSString *, CSASAuthorizationRight *> *rights;

@end

static NSString * const rightsKey = @"com.charlessoft.CSAuthSample.CSASCommandSet.Rights";
static NSString * const countKey = @"com.charlessoft.CSAuthSample.CSASCommandSet.Count";
static NSString * const rightNameKey = @"com.charlessoft.CSAuthSample.CSASCommandSet.RightName";
static NSString * const rightValueKey = @"com.charlessoft.CSAuthSample.CSASCommandSet.RightValue";

@implementation CSASCommandSet

- (instancetype)initWithAuthorizationRights:(NSArray<CSASAuthorizationRight *> *)rights {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    NSMutableDictionary *rightsDict = [NSMutableDictionary new];
    
    for (CSASAuthorizationRight *eachRight in rights) {
        rightsDict[NSStringFromSelector(eachRight.selector)] = eachRight;
    }
    
    [self addBuiltInAuthorizationRights:rightsDict];
    
    self->_rights = [rightsDict copy];
    
    return self;
}

- (NSArray <CSASAuthorizationRight *> *)authorizationRights {
    return self.rights.allValues;
}

- (void)addBuiltInAuthorizationRights:(NSMutableDictionary *)rightsDict {
    // Add built-in commands
    
    SEL connectSel = @selector(getEndpointWithAuthorizationData:endpoint:);
    NSString *connectName = NSStringFromSelector(connectSel);
    if (rightsDict[connectName] == nil) {
        NSString *rightName = @"com.charlessoft.CSAuthSample.ConnectWithEndpoint";
        const char *rule = kAuthorizationRuleClassAllow;
        
        rightsDict[connectName] = [[CSASAuthorizationRight alloc] initWithSelector:connectSel
                                                                              name:rightName
                                                                              rule:rule
                                                                            prompt:nil];
    }
    
    SEL versionSel = @selector(getVersionWithReply:);
    NSString *versionName = NSStringFromSelector(versionSel);
    if (rightsDict[versionName] == nil) {
        NSString *rightName = @"com.charlessoft.CSAuthSample.GetVersion";
        const char *rule = kAuthorizationRuleClassAllow;
        
        rightsDict[versionName] = [[CSASAuthorizationRight alloc] initWithSelector:versionSel
                                                                              name:rightName
                                                                              rule:rule
                                                                            prompt:nil];
    }
    
    SEL uninstallSel = @selector(uninstallHelperToolWithAuthorizationData:reply:);
    NSString *uninstallName = NSStringFromSelector(uninstallSel);
    if (rightsDict[uninstallName] == nil) {
        NSString *rightName = @"com.charlessoft.CSAuthSample.UninstallHelper";
        const char *rule = kAuthorizationRuleClassAllow;
        
        rightsDict[versionName] = [[CSASAuthorizationRight alloc] initWithSelector:uninstallSel
                                                                              name:rightName
                                                                              rule:rule
                                                                            prompt:nil];
    }
}

- (nullable CSASAuthorizationRight *)authorizationRightForCommand:(SEL)command {
    return self.rights[NSStringFromSelector(command)];
}

- (void)setupAuthorizationRights:(AuthorizationRef)authRef bundle:(nullable NSBundle *)bundle tableName:(nullable NSString *)tableName {
    assert(authRef != NULL);
    
    for (CSASAuthorizationRight *eachRight in self.rights.allValues) {
        // First get the right.  If we get back errAuthorizationDenied that means there's
        // no current definition, so we add our default one.

        const char *rightName = (const char * _Nonnull)eachRight.name.UTF8String;
        assert(rightName != NULL);
        
        CFBundleRef cfBundle = NULL;
        if (bundle != nil) {
            if (bundle == [NSBundle mainBundle]) {
                cfBundle = CFBundleGetMainBundle();
                CFRetain(cfBundle);
            } else {
                cfBundle = CFBundleCreate(kCFAllocatorDefault, (__bridge CFURLRef)bundle.bundleURL);
            }
        }
        
        OSStatus err = AuthorizationRightGet(rightName, NULL);
        if (err == errAuthorizationDenied) {
            err = AuthorizationRightSet(
                                        authRef,
                                        rightName,
                                        (__bridge CFTypeRef)eachRight.rule,
                                        (__bridge CFStringRef)eachRight.prompt,
                                        cfBundle,
                                        (__bridge CFStringRef)tableName
                                        );
            assert(err == errAuthorizationSuccess);
        } else {
            // A right already exists (err == noErr) or any other error occurs, we
            // assume that it has been set up in advance by the system administrator or
            // this is the second time we've run.  Either way, there's nothing more for
            // us to do.
        }
        
        if (cfBundle != NULL) {
            CFRelease(cfBundle);
        }
    }
}

+ (BOOL)supportsSecureCoding { return YES; }

- (nullable instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    NSInteger count = [coder decodeIntegerForKey:countKey];
    NSData *rightsData = [coder decodeObjectOfClass:[NSData class] forKey:rightsKey];
    
    NSKeyedUnarchiver *unarchiver;
    
    if (@available(macOS 10.13, *)) {
        unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:rightsData error:NULL];
    } else {
        unarchiver = [[NSKeyedUnarchiver alloc] initForReadingWithData:rightsData];
    }
    
    if (unarchiver == nil) {
        return nil;
    }
    
    NSMutableDictionary<NSString *, CSASAuthorizationRight *> *rightsDict = [NSMutableDictionary new];
    
    for (NSInteger i = 0; i < count; i++) {
        NSString *nameKey = [rightNameKey stringByAppendingFormat:@"%ld", (long)i];
        NSString *valueKey = [rightValueKey stringByAppendingFormat:@"%ld", (long)i];
        
        NSString *name = [unarchiver decodeObjectOfClass:[NSString class] forKey:nameKey];
        CSASAuthorizationRight *value = [unarchiver decodeObjectOfClass:[CSASAuthorizationRight class] forKey:valueKey];
        
        if (name == nil || value == nil) {
            return nil;
        }
        
        rightsDict[name] = value;
    }
    
    self->_rights = [rightsDict copy];
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    NSKeyedArchiver *archiver;
    NSData *data;
    
    if (@available(macOS 10.13, *)) {
        archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
    } else {
        NSMutableData *mutableData = [NSMutableData new];
        archiver = [[NSKeyedArchiver alloc] initForWritingWithMutableData:mutableData];
        data = mutableData;
    }
    
    __block NSInteger count = 0;
    
    [self.rights enumerateKeysAndObjectsUsingBlock:^(NSString *name, CSASAuthorizationRight *right, __unused BOOL *stop) {
        [archiver encodeObject:name forKey:[rightNameKey stringByAppendingFormat:@"%ld", (long)count]];
        [archiver encodeObject:right forKey:[rightValueKey stringByAppendingFormat:@"%ld", (long)count]];
        
        count++;
    }];
    
    if (@available(macOS 10.13, *)) {
        data = archiver.encodedData;
    } else {
        [archiver finishEncoding];
    }
    
    [coder encodeInteger:count forKey:countKey];
    [coder encodeObject:data forKey:rightsKey];
}

@end

static NSString * const selectorKey = @"com.charlessoft.CSAuthSample.CSASAuthorizationRight.Selector";
static NSString * const nameKey = @"com.charlessoft.CSAuthSample.CSASAuthorizationRight.Name";
static NSString * const ruleKey = @"com.charlessoft.CSAuthSample.CSASAuthorizationRight.Rule";
static NSString * const promptKey = @"com.charlessoft.CSAuthSample.CSASAuthorizationRight.Prompt";

@implementation CSASAuthorizationRight

+ (BOOL)supportsSecureCoding { return YES; }

- (instancetype)initWithSelector:(SEL)selector name:(NSString *)name rule:(const char *)rule prompt:(nullable NSString *)prompt {
    self = [super init];
    if (self == nil) {
        return nil;
    }
    
    self->_selector = selector;
    self->_name = [name copy];
    
    self->_rule = (NSString * _Nonnull)[[NSString alloc] initWithUTF8String:rule];
    assert(self->_rule != nil);
    
    self->_prompt = [prompt copy];
    
    return self;
}

- (nullable instancetype)initWithCoder:(NSCoder *)coder {
    self = [super init];
    if (self == nil || !coder.allowsKeyedCoding) {
        return nil;
    }
    
    NSString *selName = [coder decodeObjectOfClass:[NSString class] forKey:selectorKey];
    
    if (selName == nil) {
        return nil;
    }
    
    self->_selector = NSSelectorFromString(selName);
    self->_name = (NSString * _Nonnull)[coder decodeObjectOfClass:[NSString class] forKey:nameKey];
    self->_rule = (NSString * _Nonnull)[coder decodeObjectOfClass:[NSString class] forKey:ruleKey];
    self->_prompt = (NSString * _Nonnull)[coder decodeObjectOfClass:[NSString class] forKey:promptKey];
    
    if (self->_selector == NULL || self->_name == nil || self->_rule == nil) {
        return nil;
    }
    
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:NSStringFromSelector(self->_selector) forKey:selectorKey];
    [coder encodeObject:self->_name forKey:nameKey];
    [coder encodeObject:self->_rule forKey:ruleKey];
    
    if (self->_prompt != nil) {
        [coder encodeObject:self->_prompt forKey:promptKey];
    }
}

@end

extern NSError *CSASConvertOSStatus(OSStatus err) {
    // Prefer POSIX errors over OSStatus ones if possible, as they tend to present nicer error messages to the end user.
    
    if ((err >= errSecErrnoBase) && (err <= errSecErrnoLimit)) {
        return [[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:err - errSecErrnoBase userInfo:nil];
    } else {
        NSString *errStr = CFBridgingRelease(SecCopyErrorMessageString(err, NULL));
        NSDictionary *userInfo = nil;
        
        if (errStr != nil) {
            userInfo = @{ NSLocalizedFailureReasonErrorKey : errStr };
        }
        
        return [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:err userInfo:userInfo];
    }
}

NS_ASSUME_NONNULL_END
