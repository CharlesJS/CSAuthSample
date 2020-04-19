//
//  CSASHelperConnectionWrapper.h
//  Helper Library
//
//  Created by Charles Srstka on 4/19/20.
//

@import Foundation;

NS_ASSUME_NONNULL_BEGIN

@class CSASHelperTool;
@class CSASCommandSet;

@interface CSASHelperConnectionWrapper : NSProxy

- (instancetype)initWithConnectionClass:(Class)connectionClass
                          xpcConnection:(NSXPCConnection *)xpcConnection
                             helperTool:(CSASHelperTool *)helperTool
                             commandSet:(CSASCommandSet *)commandSet;

@end

NS_ASSUME_NONNULL_END
