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

#ifndef CSAuthSampleCommonLib_h
#define CSAuthSampleCommonLib_h

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#if 0
}     // get rid of the annoying auto-indent
#endif
#endif

/////////////////////////////////////////////////////////////////

/*
 This header has extensive HeaderDoc comments.  To see these comments in a more
 felicitous form, you can generate HTML from the HeaderDoc comments using the
 following command:
 
 $ headerdoc2html BetterAuthorizationSampleLib.h
 $ open BetterAuthorizationSampleLib/index.html
 */

/*!
 @header         BetterAuthorizationSampleLib
 
 @abstract       Reusable library for creating helper tools that perform privileged
 operations on behalf of your application.
 
 @discussion     BetterAuthorizationSampleLib allows you to perform privileged operations
 in a helper tool. In this model, your application runs with standard
 privileges and, when it needs to do a privileged operation, it makes a
 request to the helper tool.  The helper tool uses Authorization Services
 to ensure that the user is authorized to perform that operation.
 
 BetterAuthorizationSampleLib takes care of all of the mechanics of
 installing the helper tool and communicating with it.  Specifically, it
 has routines that your application can call to:
 
 1. send requests to a helper tool (CSASExecuteRequestInHelperTool)
 
 2. install the helper tool if it's not installed, or fix an installation if
 it's broken (CSASDiagnoseFailure and CSASFixFailure)
 
 BetterAuthorizationSampleLib also helps you implement the helper tool.
 Specifically, you call the routine CSASHelperToolMain in the main entry
 point for your helper tool, passing it an array of command callbacks (of
 type CSASCommandProc).  CSASHelperToolMain will take care of all the details
 of communication with the application and only call your callback to
 execute the actual command.
 
 A command consists of request and response CFDictionaries (or, equivalently,
 NSDictionaries).  BetterAuthorizationSampleLib defines three special keys for
 these dictionaries:
 
 1. kCSASCommandKey -- In the request dictionary, this is the name of the
 command. Its value is a string that uniquely identifies the command within
 your program.
 
 2. kCSASErrorKey -- In the response dictionary, this is the error result for
 the request. Its value is an OSStatus-style error code.
 
 3. kCSASDescriptorArrayKey -- In the response dictionary, if present, this is
 an array of file descriptors being returned from the helper tool.
 
 You can use any other key to represent addition parameters (or return values)
 for the command.  The only constraints that BetterAuthorizationSampleLib applies
 to these extra parameters is that they must be serialisable as a CFPropertyList.
 
 BetterAuthorizationSampleLib requires that you tell it about the list of commands
 that you support.  Each command is represented by a command specification
 (CSASCommandSpec).  The command specification includes the following information:
 
 1. The name of the command.  This is the same as the kCSASCommandKey value in
 the request dictionary.
 
 2. The authorization right associated with the command.  BetterAuthorizationSampleLib
 uses this to ensure that the user is authorized to use the command before
 it calls your command callback in the privileged helper tool.
 
 3. Information to create the command's authorization right specification in the
 policy database.  The is used by the CSASSetDefaultRules function.
 
 Finally, BetterAuthorizationSampleLib includes a number of utilities routines to help
 wrangle error codes (CSASErrnoToOSStatus, CSASOSStatusToErrno, and CSASGetErrorFromResponse)
 and file descriptors (CSASCloseDescriptorArray).
 */

/////////////////////////////////////////////////////////////////
#pragma mark ***** Command Description

/*!
 @struct         CSASCommandSpec
 
 @abstract       Describes a privileged operation to BetterAuthorizationSampleLib.
 
 @discussion     Both the application and the tool must tell BetterAuthorizationSampleLib about
 the operations (that is, commands) that they support.  They do this by passing
 in an array of CSASCommandSpec structures.  Each element describes one command.
 The array is terminated by a command whose commandName field is NULL.
 
 In general the application and tool should use the same array definition.
 However, there are cases where these might be out of sync.  For example, if you
 have an older version of the application talking to a newer version of the tool,
 the tool might know about more commands than the application (and thus provide a
 longer array), and that's OK.
 
 @field commandName
 A identifier for this command.  This can be any string that is unique within
 the context of your programs.  A NULL value in this field terminates the array.
 
 The length of the command name must not be greater than 1024 UTF-16 values.
 
 @field rightName
 This is the name of the authorization right associated with the
 command.  This can be NULL if you don't want any right associated with the
 command.  If it's not NULL, BetterAuthorizationSampleLib will acquire that right
 before allowing the command to execute.
 
 @field rightDefaultRule
 This is the name of an authorization rule that should be used in
 the default right specification for the right.  To see a full list of these rules,
 look at the "rules" dictionary within the policy database (currently
 "/etc/authorization").  Common values include "default" (which requires that the user
 hold credentials that authenticate them as an admin user) and "allow" (which will let
 anyone acquire the right).
 
 This must be NULL if (and only if) rightName is NULL.
 
 @field rightDescriptionKey
 This is a key used to form a custom prompt for the right.  The value of this
 string should be a key into a .strings file whose name you supply to
 CSASSetDefaultRules.  When BetterAuthorizationSampleLib creates the right specification,
 it uses this key to get all of the localised prompt strings for the right.
 
 This must be NULL if rightName is NULL.  Otherwise, this may be NULL if you
 don't want a custom prompt for your right.
 
 @field userData
 This field is is for the benefit of the client; BetterAuthorizationSampleLib
 does not use it in any way.
 */

struct CSASCommandSpec {
    const char *		commandName;
    const char *		rightName;
    const char *		rightDefaultRule;
    const uint64_t		rightTimeoutInSeconds;
    const char *        rightComment;
    const char *		rightDescriptionKey;
    const char *    	codeSigningRequirement;
    const void *    	userData;
};
typedef struct CSASCommandSpec CSASCommandSpec;

//////////////////////////////////////////////////////////////////////////////////
#pragma mark ***** Constants

// The key used to get the request dictionary in the XPC request.

#define kCSASRequestKey              "Request"

// The key used to get our flattened AuthorizationRef in the XPC request.

#define kCSASAuthorizationRefKey     "AuthorizationRef"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Authorization Rules

/*!
 Some constants defining authorization rules, for use in SampleCommon.h.
 */

// Allow anyone.
#define kCSASRuleAllow 								"kCSASRuleAllow"

// Deny anyone.
#define kCSASRuleDeny								"kCSASRuleDeny"

// Authenticate as an administrator.
// An acquired credential is *not* shared by all clients.
#define kCSASRuleAuthenticateAdmin					"kCSASRuleAuthenticateAdmin"

// Authenticate as a developer.
#define kCSASRuleAuthenticateDeveloper				"kCSASRuleAuthenticateDeveloper"

// Authenticate as the session owner.
#define kCSASRuleAuthenticateSessionOwner			"kCSASRuleAuthenticateSessionOwner"

// Authenticate either as the owner or as an administrator.
#define kCSASRuleAuthenticateSessionOwnerOrAdmin	"kCSASRuleAuthenticateSessionOwnerOrAdmin"

// Verify that the user asking for authorization is an administrator.
#define kCSASRuleIsAdmin							"kCSASRuleIsAdmin"

// Verify that the user asking for authorization is a developer.
#define kCSASRuleIsDeveloper						"kCSASRuleIsDeveloper"

// Verify that the process that created this AuthorizationRef is running as root.
#define kCSASRuleIsRoot								"kCSASRuleIsRoot"

// Verify that the requesting process is running as the session owner.
#define kCSASRuleIsSessionOwner						"kCSASRuleIsSessionOwner"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Request/Response Keys

// Standard keys for the request dictionary

/*!
 @define         kCSASCommandKey
 
 @abstract       Key for the command string within the request dictionary.
 
 @discussion     Within a request, this key must reference a string that is the name of the
 command to execute.  This must match one of the commands in the
 CSASCommandSpec array.
 
 The length of a command name must not be greater than 1024 UTF-16 values.
 */

#define kCSASCommandKey      "com.charlessoft.CSAuthSample.command"			// CFString

// Standard keys for the response dictionary

/*!
 @define         kCSASErrorKey
 
 @abstract       Key for the error result within the response dictionary.
 
 @discussion     Within a response, this key must reference a number that is the error result
 for the response, interpreted as an OSStatus.
 */

#define kCSASErrorKey         "com.charlessoft.CSAuthSample.error"				// CFDictionary

#define kCSASErrorDomainKey   "com.charlessoft.CSAuthSample.error.domain"		// CFString
#define kCSASErrorCodeKey     "com.charlessoft.CSAuthSample.error.code"			// CFNumber
#define kCSASErrorUserInfoKey "com.charlessoft.CSAuthSample.error.userInfo"		// CFDictionary

/*!
 @define         kBASDescriptorArrayKey
 
 @abstract       Key for a file descriptor array within the response dictionary.
 
 @discussion     Within a response, this key, if present, must reference an array
 of numbers, which are the file descriptors being returned with
 the response.  The numbers are interpreted as ints.
 */

#define kCSASDescriptorArrayKey "com.charlessoft.CSAuthSample.descriptors"	// CFArray of CFNumber

#define kCSASCanAcceptFurtherInputKey "com.charlessoft.CSAuthSample.canAcceptFurtherInput"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Utility Routines

/*!
 @functiongroup  Utilities
 */

// Our very own error domain.
extern CFStringRef const kCSASErrorDomain;

// Possible errors that could be returned with kCSASErrorDomain.

enum {
    kCSASErrorSuccess,
    kCSASErrorConnectionInterrupted,
    kCSASErrorConnectionInvalid,
    kCSASErrorUnexpectedConnection,
    kCSASErrorUnexpectedEvent
};

extern CFErrorRef CSASCreateCFErrorFromErrno(int errNum, CFURLRef url);
extern CFErrorRef CSASCreateCFErrorFromOSStatus(OSStatus err, CFURLRef url);

extern char *CSASCreateFileSystemRepresentationForURL(CFURLRef url, CFErrorRef *error);
extern char *CSASCreateFileSystemRepresentationForPath(CFStringRef path);

extern CFTypeRef CSASCreateCFTypeFromXPCMessage(xpc_object_t message);
extern xpc_object_t CSASCreateXPCMessageFromCFType(CFTypeRef obj);

extern void CSASLog(CFStringRef format, ...) CF_FORMAT_FUNCTION(1, 2);

extern bool CSASFindCommand(
                            CFStringRef                 commandName,
                            const CSASCommandSpec		commands[],
                            size_t *                    commandIndexPtr,
                            CFErrorRef *                errorPtr
                            );

#ifdef __cplusplus
}
#endif

#endif
