//
//  CSASHelperConnectionWrapper.m
//  Helper Library
//
//  Created by Charles Srstka on 4/19/20.
//

@import ObjectiveC.runtime;
#import "CSASHelperConnectionWrapper.h"
#import "CSASHelperConnection.h"
#import "CSASHelperTool.h"
#import "CSASHelperToolInternal.h"
#import "CSASHelperConnectionInternal.h"

@interface CSASHelperConnectionWrapper ()

@property (nonatomic, readonly) CSASHelperConnection *connection;

@end

@implementation CSASHelperConnectionWrapper

- (instancetype)initWithConnectionClass:(Class)connectionClass
                          xpcConnection:(NSXPCConnection *)xpcConnection
                             helperTool:(CSASHelperTool *)helperTool
                             commandSet:(CSASCommandSet *)commandSet {
    self->_connection = [(CSASHelperConnection *)[connectionClass alloc] initWithConnection:xpcConnection
                                                                                 helperTool:helperTool
                                                                                 commandSet:commandSet];
    
    return self;
}

- (BOOL)respondsToSelector:(SEL)selector { return [self.connection respondsToSelector:selector]; }
- (NSMethodSignature *)methodSignatureForSelector:(SEL)sel { return [self.connection methodSignatureForSelector:sel]; }
- (BOOL)conformsToProtocol:(Protocol *)protocol { return [self.connection conformsToProtocol:protocol]; }

- (void)forwardInvocation:(NSInvocation *)invocation {
    self.connection.currentCommand = invocation.selector;
    [invocation invokeWithTarget:self.connection];
}

@end
