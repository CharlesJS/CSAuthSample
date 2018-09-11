//
//  CSASHelperConnection.h
//  ObjC Helper Tool
//
//  Created by Charles Srstka on 7/1/18.
//

@import Foundation;
#import "CSASHelperTool.h"
#import "CSASCommon.h"

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(HelperConnection) @interface CSASHelperConnection : NSObject <CSASBuiltInCommands>

@property (nonatomic, readonly) NSXPCConnection *connection;
@property (nonatomic, readonly) CSASCommandSet *commandSet;

- (instancetype)initWithConnection:(NSXPCConnection *)connection
                        helperTool:(CSASHelperTool *)helperTool
                        commandSet:(CSASCommandSet *)commandSet;

// Make sure to call this method at the beginning of every command.
// For the 'command' parameter, pass _cmd.
- (BOOL)checkAuthorization:(NSData *)authData
                forCommand:(SEL)command
                     error:(__autoreleasing NSError * _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
