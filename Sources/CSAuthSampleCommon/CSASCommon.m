//
//  CSASCommon.m
//  Helper Library
//
//  Based on Common.m from EvenBetterAuthorizationSample,
//  Copyright © 2013 Apple Computer.
//
//  Created by Charles Srstka on 6/25/18.
//

@import Foundation;
@import Darwin.POSIX.syslog;
#import "CSASCommon.h"

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
        
        rightsDict[uninstallName] = [[CSASAuthorizationRight alloc] initWithSelector:uninstallSel
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
    
    NSKeyedUnarchiver *unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:rightsData error:NULL];

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
    NSKeyedArchiver *archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];

    __block NSInteger count = 0;
    
    [self.rights enumerateKeysAndObjectsUsingBlock:^(NSString *name, CSASAuthorizationRight *right, __unused BOOL *stop) {
        [archiver encodeObject:name forKey:[rightNameKey stringByAppendingFormat:@"%ld", (long)count]];
        [archiver encodeObject:right forKey:[rightValueKey stringByAppendingFormat:@"%ld", (long)count]];
        
        count++;
    }];
    
    NSData *data = archiver.encodedData;
    
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

static NSInteger CSASConvertPOSIXErrorCode(NSInteger code) {
    switch (code) {
        case ECANCELED:
            return NSUserCancelledError;
        case ENOENT:
            return NSFileNoSuchFileError;
        case EFBIG:
            return NSFileReadTooLargeError;
        case EEXIST:
            return NSFileWriteFileExistsError;
        case ENOSPC:
            return NSFileWriteOutOfSpaceError;
        case EROFS:
            return NSFileWriteVolumeReadOnlyError;
        default:
            return 0;
    }
}

static NSInteger CSASConvertOSStatusErrorCode(NSInteger code) {
    if (code >= errSecErrnoBase && code <= errSecErrnoLimit) {
        NSInteger newCode = CSASConvertPOSIXErrorCode(code - errSecErrnoBase);
        
        if (newCode != 0) {
            return newCode;
        }
    }
    
    switch (code) {
        case userCanceledErr:
        case errAuthorizationCanceled:
        case errSecCSCancelled:
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
            return NSUserCancelledError;
        case fnfErr:
            return NSFileNoSuchFileError;
        case fileBoundsErr:
        case fsDataTooBigErr:
            return NSFileReadTooLargeError;
        case dupFNErr:
            return NSFileWriteFileExistsError;
        case dskFulErr:
        case errFSNotEnoughSpaceForOperation:
            return NSFileWriteOutOfSpaceError;
        case vLckdErr:
            return NSFileWriteVolumeReadOnlyError;
        default:
            return 0;
    }
}

FOUNDATION_EXPORT NSError *CSASConvertNSError(NSError *error) {
    // If we can find a NSCocoaError that corresponds to the same error condition as this error, use it.
    // NSCocoaError tends to present nicer error messages to the user.
    NSInteger newCode = 0;
    
    if ([error.domain isEqualToString:NSPOSIXErrorDomain]) {
        newCode = CSASConvertPOSIXErrorCode(error.code);
    } else if ([error.domain isEqualToString:NSOSStatusErrorDomain]) {
        newCode = CSASConvertOSStatusErrorCode(error.code);
    } else {
        newCode = 0;
    }
    
    if (newCode != 0) {
        NSMutableDictionary *userInfo = error.userInfo.mutableCopy;
        
        userInfo[NSUnderlyingErrorKey] = error;
        
        // Use the built-in error messages instead
        userInfo[NSLocalizedFailureReasonErrorKey] = nil;
        
        return [[NSError alloc] initWithDomain:NSCocoaErrorDomain code:newCode userInfo:userInfo];
    } else if ([error.domain isEqualToString:NSOSStatusErrorDomain]) {
        // At least try to find a nicer error string to display to the user.
        
        CFStringRef errString = SecCopyErrorMessageString((OSStatus)error.code, NULL);
        
        if (errString != NULL) {
            NSMutableDictionary *userInfo = error.userInfo.mutableCopy;
            
            userInfo[NSLocalizedFailureReasonErrorKey] = CFBridgingRelease(errString);
            
            return [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:error.code userInfo:userInfo];
        }
    }
    
    // We weren't able to improve this error message; just return it as is
    return error;
}

FOUNDATION_EXPORT NSError *CSASConvertCFError(CFErrorRef error) {
    return CSASConvertNSError((__bridge NSError *)error);
}

FOUNDATION_EXPORT NSError *CSASConvertPOSIXError(int err) {
    return CSASConvertNSError([[NSError alloc] initWithDomain:NSPOSIXErrorDomain code:err userInfo:nil]);
}

FOUNDATION_EXPORT NSError *CSASConvertOSStatus(OSStatus err) {
    return CSASConvertNSError([[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:err userInfo:nil]);
}

NS_ASSUME_NONNULL_END
