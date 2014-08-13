/*
 File:       BetterAuthorizationSampleLib.h
 
 Contains:   Interface to reusable code for privileged helper tools.
 
 Written by: DTS
 
 Modified by Charles Srstka, 2013.
 
 Copyright:  Copyright (c) 2007 Apple Inc. All Rights Reserved.
 
 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple, Inc.
 ("Apple") in consideration of your agreement to the following terms, and your
 use, installation, modification or redistribution of this Apple software
 constitutes acceptance of these terms.  If you do not agree with these terms,
 please do not use, install, modify or redistribute this Apple software.
 
 In consideration of your agreement to abide by the following terms, and subject
 to these terms, Apple grants you a personal, non-exclusive license, under Apple's
 copyrights in this original Apple software (the "Apple Software"), to use,
 reproduce, modify and redistribute the Apple Software, with or without
 modifications, in source and/or binary forms; provided that if you redistribute
 the Apple Software in its entirety and without modifications, you must retain
 this notice and the following text and disclaimers in all such redistributions of
 the Apple Software.  Neither the name, trademarks, service marks or logos of
 Apple, Inc. may be used to endorse or promote products derived from the
 Apple Software without specific prior written permission from Apple.  Except as
 expressly stated in this notice, no other rights or licenses, express or implied,
 are granted by Apple herein, including but not limited to any patent rights that
 may be infringed by your derivative works or by other works in which the Apple
 Software may be incorporated.
 
 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED
 WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 COMBINATION WITH YOUR PRODUCTS.
 
 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
 OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT
 (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 */

#import <Foundation/Foundation.h>
#include "CSAuthSampleCommonLib.h"

@class CSASHelperConnection;

typedef void (^CSASResponseHandler)(NSDictionary *response, NSArray *fileHandles, CSASHelperConnection *persistentConnection, NSError *errorOrNil);

@interface CSASRequestSender : NSObject

@property (strong) NSOperationQueue *operationQueue;

- (instancetype)initWithCommandSet:(const CSASCommandSpec *)commands helperID:(NSString *)helperID error:(NSError *__autoreleasing *)error;

// Make sure this is called before your application exits.
- (void)cleanUp;

- (BOOL)blessHelperToolAndReturnError:(NSError *__autoreleasing *)error;

- (void)requestHelperVersion:(void (^)(NSString *version, NSError *errorOrNil))handler;

/*!
 @function       CSASExecuteRequestInHelperTool
 
 @abstract       Executes a request in the privileged helper tool, returning the response.
 
 @discussion     This routine synchronously executes a request in the privileged helper tool and
 returns the response.
 
 If the function returns an error, the IPC between your application and the helper tool
 failed.  Unfortunately it's not possible to tell whether this failure occurred while
 sending the request or receiving the response, thus it's not possible to know whether
 the privileged operation was done or not.
 
 If the functions returns no error, the IPC between your application and the helper tool
 was successful.  However, the command may still have failed.  You must get the error
 value from the response (typically using CSASGetErrorFromResponse) to see if the
 command succeeded or not.
 
 On success the response dictionary may contain a value for the kCSASDescriptorArrayKey key.
 If so, that will be a non-empty CFArray of CFNumbers, each of which can be accessed as an int.
 Each value is a descriptor that is being returned to you from the helper tool.  You are
 responsible for closing these descriptors when you're done with them.
 
 @param auth     A reference to your program's authorization instance; you typically get this
 by calling AuthorizationCreate.
 
 This must not be NULL.
 
 @param commands An array that describes the commands that you implement, and their associated
 rights.  There must be at least one valid command.
 
 @param bundleID The bundle identifier for your program.
 
 This must not be NULL.
 
 @param request  A dictionary describing the requested operation.  This must, at least, contain
 a string value for the kCSASCommandKey.  Furthermore, this string must match
 one of the commands in the array.
 
 The dictionary may also contain other values.  These are passed to the helper
 tool unintepreted.  All values must be serialisable using the CFPropertyList
 API.
 
 This must not be NULL.
 
 @param response This must not be NULL.  On entry, *response must be NULL.  On success, *response
 will not be NULL.  On error, *response will be NULL.
 
 On success, you are responsible for disposing of *response.  You are also
 responsible for closing any descriptors returned in the response.
 
 @result			An OSStatus code (see CSASErrnoToOSStatus and CSASOSStatusToErrno).
 */

- (void)executeCommandInHelperTool:(NSString *)commandName userInfo:(NSDictionary *)userInfo responseHandler:(CSASResponseHandler)responseHandler;

@end

@interface CSASHelperConnection : NSObject

@property (readonly) BOOL isValid;

- (void)sendMessage:(NSDictionary *)message responseHandler:(CSASResponseHandler)responseHandler;

- (void)closeConnection;

@end
