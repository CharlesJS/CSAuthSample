//
//  CSASHelperTool.h
//  CSAuthSample
//
//  Created by Charles Srstka on 6/25/18.
//

@import Foundation;
#import "CSASCommon.h"

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(HelperTool) @interface CSASHelperTool: NSObject

@property (nonatomic, readonly) NSString *helperID;

// If nil is passed for senderRequirements, the value for the
// "SMAuthorizedClients" key will be read from the helper tool's
// built-in Info.plist.

- (instancetype)initWithHelperID:(NSString *)helperID
                      commandSet:(CSASCommandSet *)commandSet
              senderRequirements:(nullable NSArray<NSString *> *)senderRequirements
                 connectionClass:(Class)connectionClass // must be CSASHelperConnection subclass
                        protocol:(Protocol *)protocol;

- (instancetype)initWithHelperID:(NSString *)helperID
                      commandSet:(CSASCommandSet *)commandSet
              senderRequirements:(nullable NSArray<NSString *> *)senderRequirements
                 connectionClass:(Class)connectionClass // must be CSASHelperConnection subclass
                       interface:(NSXPCInterface *)interface;

- (void)run __attribute__((noreturn));

// Do any security checks prior to allowing a connection.
// The default implementation checks the calling process's code signature
// to make sure it matches one of the requirements passed in the
// senderRequirements parameter when initializing the object.
- (BOOL)shouldApproveConnection:(NSXPCConnection *)connection;

// Check the code signature of an arbitrary NSXPCConnection and requirement.
// This can be useful if you are establishing additional connections from the helper.
- (BOOL)checkCodeSigningForConnection:(NSXPCConnection *)connection
                          requirement:(NSString *)req
                                error:(__autoreleasing NSError * _Nullable * _Nullable)error;

// Logging methods that wrap the syslog(3) command.
// Priority constants are defined in <sys/syslog.h>. Default is LOG_NOTICE.
- (void)log:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (void)logWithPriority:(int)priority format:(NSString *)format, ... NS_FORMAT_FUNCTION(2, 3);
- (void)logWithPriority:(int)priority format:(NSString *)format arguments:(va_list)args NS_FORMAT_FUNCTION(2,0);

@end

NS_ASSUME_NONNULL_END
