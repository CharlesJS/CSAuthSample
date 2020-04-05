//
//  CSASCommon.h
//  Helper Library
//
//  Created by Charles Srstka on 6/25/18.
//

@import Foundation;

NS_ASSUME_NONNULL_BEGIN

// Some built-in commands handled by the library which are provided for free.
// The protocol you pass to CSASHelperTool should conform to this protocol.
//
// IMPORTANT: NSXPCConnection can call these methods on any thread.  It turns out that our
// implementation of these methods is thread safe but if that's not the case for your code
// you have to implement your own protection (for example, having your own serial queue and
// dispatching over to it).

NS_SWIFT_NAME(BuiltInCommands) @protocol CSASBuiltInCommands

// Part of CSASBuiltInCommands.  Not used by the standard app (it's part of the sandboxed
// XPC service support).  Called by the XPC service to get an endpoint for our listener.  It then
// passes this endpoint to the app so that the sandboxed app can talk us directly.
- (void)getEndpointWithAuthorizationData:(NSData *)authData
                                endpoint:(void (^)(NSXPCListenerEndpoint * _Nullable, NSError * _Nullable))reply
NS_SWIFT_NAME(connect(authorizationData:endpoint:));

// Part of CSASBuiltInCommands. Returns the version number of the tool.
- (void)getVersionWithReply:(void(^)(NSString * _Nullable version, NSError * _Nullable))reply
NS_SWIFT_NAME(getVersion(reply:));

// Part of CSASBuiltInCommands. Uninstalls the helper tool.
- (void)uninstallHelperToolWithAuthorizationData:(NSData *)authData
                                           reply:(void (^)(NSError * _Nullable))reply
NS_SWIFT_NAME(uninstallHelperTool(authorizationData:reply:));

@end

NS_SWIFT_NAME(AuthorizationRight) @interface CSASAuthorizationRight: NSObject <NSSecureCoding>

- (instancetype)initWithSelector:(SEL)selector
                            name:(NSString *)name
                            rule:(const char *)rule
                          prompt:(nullable NSString *)prompt;

@property (nonatomic)                 SEL selector;
@property (nonatomic, copy)           NSString *name;
@property (nonatomic, copy)           NSString *rule;
@property (nonatomic, copy, nullable) NSString *prompt;

@end

NS_SWIFT_NAME(CommandSet) @interface CSASCommandSet: NSObject <NSSecureCoding>

- (instancetype)initWithAuthorizationRights:(NSArray<CSASAuthorizationRight *> *)rights;

@property (nonatomic, readonly) NSArray<CSASAuthorizationRight *> *authorizationRights;

// For a given command selector, return the associated authorization right name.
- (nullable CSASAuthorizationRight *)authorizationRightForCommand:(SEL)command;

// Set up the default authorization rights in the authorization database.
- (void)setupAuthorizationRights:(AuthorizationRef)authRef
                          bundle:(nullable NSBundle *)bundle
                       tableName:(nullable NSString *)tableName;

@end

// Cocoa tends to do a nicer job presenting Cocoa errors than POSIX or OSStatus ones,
// particularly with NSUserCancelledError, in which case -presentError: will skip
// showing the error altogether. For certain other error types, using the Cocoa domain
// will provide a little more information, including, sometimes, the filename for which
// the operation failed. Therefore, convert errors to NSCocoaErrorDomain when possible.

FOUNDATION_EXPORT NSError *CSASConvertNSError(NSError *error) NS_SWIFT_NAME(ConvertError(_:));
FOUNDATION_EXPORT NSError *CSASConvertCFError(CFErrorRef error) NS_SWIFT_NAME(ConvertCFError(_:));
FOUNDATION_EXPORT NSError *CSASConvertPOSIXError(int err) NS_SWIFT_NAME(ConvertPOSIXError(_:));
FOUNDATION_EXPORT NSError *CSASConvertOSStatus(OSStatus status) NS_SWIFT_NAME(ConvertOSStatus(_:));

NS_ASSUME_NONNULL_END
