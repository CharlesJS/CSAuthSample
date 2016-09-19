// CSAuthSampleAppLib.h
// Copyright Charles Srstka, 2013-2016.
// Based on "BetterAuthorizationSampleLib.h" by Apple Computer.

#import <Foundation/Foundation.h>
#include "CSAuthSampleCommonLib.h"

@class CSASHelperConnection;

typedef void (^CSASResponseHandler)(NSDictionary<NSString *, id> * _Nonnull response, NSArray<NSFileHandle *> * _Nonnull fileHandles, CSASHelperConnection * _Nullable persistentConnection, NSError * _Nullable errorOrNil);

@interface CSASRequestSender : NSObject

@property (strong, nullable) NSOperationQueue *operationQueue;

- (nullable instancetype)initWithCommandSet:(nonnull NSDictionary<NSString *, NSDictionary<NSString *, id> *> *)commandSet helperID:(nonnull NSString *)helperID error:(NSError * _Nullable __autoreleasing * _Nullable)error;

// Make sure this is called before your application exits.
- (void)cleanUp;

- (BOOL)blessHelperToolAndReturnError:(NSError * _Nullable __autoreleasing * _Nullable)error;

- (void)removeHelperTool:(nullable void (^)(NSError * _Nullable errorOrNil))handler;

- (void)requestHelperVersion:(nonnull void (^)(NSString * _Nonnull version, NSError * _Nullable errorOrNil))handler;

- (void)executeCommandInHelperTool:(nonnull NSString *)commandName userInfo:(nullable NSDictionary<NSString *, id> *)userInfo responseHandler:(nullable CSASResponseHandler)responseHandler;

@end

@interface CSASHelperConnection : NSObject

@property (readonly) BOOL isValid;

- (void)sendMessage:(nonnull NSDictionary<NSString *, id> *)message responseHandler:(nullable CSASResponseHandler)responseHandler;

- (void)closeConnection;

@end
