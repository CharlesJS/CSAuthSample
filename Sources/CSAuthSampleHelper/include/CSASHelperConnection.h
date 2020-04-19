//
//  CSASHelperConnection.h
//  Helper Tool
//
//  Created by Charles Srstka on 7/1/18.
//

@import Foundation;
@import CSAuthSampleCommon;
#import "CSASHelperTool.h"

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(HelperConnection) @interface CSASHelperConnection : NSObject <CSASBuiltInCommands>

@property (nonatomic, readonly) NSXPCConnection *connection;
@property (nonatomic, readonly) CSASCommandSet *commandSet;

- (instancetype)initWithConnection:(NSXPCConnection *)connection
                        helperTool:(CSASHelperTool *)helperTool
                        commandSet:(CSASCommandSet *)commandSet;

// This method must be called at the beginning of every command, before executing any other code.
// Returns nil on successful authorization, and an `NSError` otherwise.

- (nullable NSError *)checkAuthorization:(NSData *)authData;

@end

NS_ASSUME_NONNULL_END
