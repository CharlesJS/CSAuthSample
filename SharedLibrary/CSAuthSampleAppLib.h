// CSAuthSampleAppLib.h
// Copyright Charles Srstka, 2013-2015.
// Based on "BetterAuthorizationSampleLib.h" by Apple Computer.

#import <Foundation/Foundation.h>
#include "CSAuthSampleCommonLib.h"

@class CSASHelperConnection;

typedef void (^CSASResponseHandler)(NSDictionary<NSString *, id> *response, NSArray<NSFileHandle *> *fileHandles, CSASHelperConnection *persistentConnection, NSError *errorOrNil);

@interface CSASRequestSender : NSObject

@property (strong) NSOperationQueue *operationQueue;

- (instancetype)initWithCommandSet:(NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)commandSet helperID:(NSString *)helperID error:(NSError *__autoreleasing *)error;

// Make sure this is called before your application exits.
- (void)cleanUp;

- (BOOL)blessHelperToolAndReturnError:(NSError *__autoreleasing *)error;

- (void)removeHelperTool:(void (^)(NSError *errorOrNil))handler;

- (void)requestHelperVersion:(void (^)(NSString *version, NSError *errorOrNil))handler;

- (void)executeCommandInHelperTool:(NSString *)commandName userInfo:(NSDictionary<NSString *, id> *)userInfo responseHandler:(CSASResponseHandler)responseHandler;

@end

@interface CSASHelperConnection : NSObject

@property (readonly) BOOL isValid;

- (void)sendMessage:(NSDictionary<NSString *, id> *)message responseHandler:(CSASResponseHandler)responseHandler;

- (void)closeConnection;

@end
