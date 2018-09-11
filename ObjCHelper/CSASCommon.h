//
//  CSASCommon.h
//  ObjC Helper Library
//
//  Created by Charles Srstka on 6/25/18.
//

@import Foundation;

NS_ASSUME_NONNULL_BEGIN

extern NSError *CSASConvertOSStatus(OSStatus status) NS_SWIFT_NAME(ConvertOSStatus(_:));

// Some built-in commands handled by the library which are provided for free.
NS_SWIFT_NAME(BuiltInCommands) @protocol CSASBuiltInCommands

- (void)getEndpointWithAuthorizationData:(NSData *)authData
                                endpoint:(void (^)(NSXPCListenerEndpoint * _Nullable, NSError * _Nullable))reply
NS_SWIFT_NAME(connect(authorizationData:endpoint:));

- (void)getVersionWithReply:(void(^)(NSString * _Nullable version, NSError * _Nullable))reply
NS_SWIFT_NAME(getVersion(reply:));

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

NS_ASSUME_NONNULL_END
