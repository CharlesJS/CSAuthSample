// CSAuthSampleAppLib.h
// Copyright Charles Srstka, 2013-2014.
// Based on "BetterAuthorizationSampleLib.h" by Apple Computer.

#import <Foundation/Foundation.h>
#include "CSAuthSampleCommonLib.h"

@class CSASHelperConnection;

typedef void (^CSASResponseHandler)(NSDictionary *response, NSArray *fileHandles, CSASHelperConnection *persistentConnection, NSError *errorOrNil);

@interface CSASRequestSender : NSObject

@property (strong) NSOperationQueue *operationQueue;

- (instancetype)initWithCommandSet:(NSDictionary *)commandSet helperID:(NSString *)helperID error:(NSError *__autoreleasing *)error;

// Make sure this is called before your application exits.
- (void)cleanUp;

- (BOOL)blessHelperToolAndReturnError:(NSError *__autoreleasing *)error;

- (void)requestHelperVersion:(void (^)(NSString *version, NSError *errorOrNil))handler;

- (void)executeCommandInHelperTool:(NSString *)commandName userInfo:(NSDictionary *)userInfo responseHandler:(CSASResponseHandler)responseHandler;

@end

@interface CSASHelperConnection : NSObject

@property (readonly) BOOL isValid;

- (void)sendMessage:(NSDictionary *)message responseHandler:(CSASResponseHandler)responseHandler;

- (void)closeConnection;

@end
