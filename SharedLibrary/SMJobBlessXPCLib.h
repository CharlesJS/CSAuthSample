/*
 File:       BetterAuthorizationSampleLib.h
 
 Contains:   Interface to reusable code for privileged helper tools.
 
 Written by: DTS
 
 Modified by Charles Srstka, 2012.
 
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

#ifndef _SMJobBlessXPCLib_h
#define _SMJobBlessXPCLib_h

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
    // get rid of the annoying auto-indent
#if 0
}
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
 
 1. send requests to a helper tool (SJBXExecuteRequestInHelperTool)
 
 2. install the helper tool if it's not installed, or fix an installation if
 it's broken (SJBXDiagnoseFailure and SJBXFixFailure)
 
 BetterAuthorizationSampleLib also helps you implement the helper tool.
 Specifically, you call the routine SJBXHelperToolMain in the main entry
 point for your helper tool, passing it an array of command callbacks (of
 type SJBXCommandProc).  SJBXHelperToolMain will take care of all the details
 of communication with the application and only call your callback to
 execute the actual command.
 
 A command consists of request and response CFDictionaries (or, equivalently,
 NSDictionaries).  BetterAuthorizationSampleLib defines three special keys for
 these dictionaries:
 
 1. kSJBXCommandKey -- In the request dictionary, this is the name of the
 command. Its value is a string that uniquely identifies the command within
 your program.
 
 2. kSJBXErrorKey -- In the response dictionary, this is the error result for
 the request. Its value is an OSStatus-style error code.
 
 3. kSJBXDescriptorArrayKey -- In the response dictionary, if present, this is
 an array of file descriptors being returned from the helper tool.
 
 You can use any other key to represent addition parameters (or return values)
 for the command.  The only constraints that BetterAuthorizationSampleLib applies
 to these extra parameters is that they must be serialisable as a CFPropertyList.
 
 BetterAuthorizationSampleLib requires that you tell it about the list of commands
 that you support.  Each command is represented by a command specification
 (SJBXCommandSpec).  The command specification includes the following information:
 
 1. The name of the command.  This is the same as the kSJBXCommandKey value in
 the request dictionary.
 
 2. The authorization right associated with the command.  BetterAuthorizationSampleLib
 uses this to ensure that the user is authorized to use the command before
 it calls your command callback in the privileged helper tool.
 
 3. Information to create the command's authorization right specification in the
 policy database.  The is used by the SJBXSetDefaultRules function.
 
 Finally, BetterAuthorizationSampleLib includes a number of utilities routines to help
 wrangle error codes (SJBXErrnoToOSStatus, SJBXOSStatusToErrno, and SJBXGetErrorFromResponse)
 and file descriptors (SJBXCloseDescriptorArray).
 */

/////////////////////////////////////////////////////////////////
#pragma mark ***** Command Description

/*!
 @struct         SJBXCommandSpec
 
 @abstract       Describes a privileged operation to BetterAuthorizationSampleLib.
 
 @discussion     Both the application and the tool must tell BetterAuthorizationSampleLib about
 the operations (that is, commands) that they support.  They do this by passing
 in an array of SJBXCommandSpec structures.  Each element describes one command.
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
 SJBXSetDefaultRules.  When BetterAuthorizationSampleLib creates the right specification,
 it uses this key to get all of the localised prompt strings for the right.
 
 This must be NULL if rightName is NULL.  Otherwise, this may be NULL if you
 don't want a custom prompt for your right.
 
 @field userData
 This field is is for the benefit of the client; BetterAuthorizationSampleLib
 does not use it in any way.
 */

struct SJBXCommandSpec {
    const char *	commandName;
    const char *	rightName;
    const char *	rightDefaultRule;
    const char *	rightDescriptionKey;
    const void *    userData;
};
typedef struct SJBXCommandSpec SJBXCommandSpec;

/////////////////////////////////////////////////////////////////
#pragma mark ***** Authorization Rules

/*!
 Some constants defining authorization rules, for use in SampleCommon.h.
 
 I'm not sure why SJBX never provided any of these, to be honest. They're quite handy.
 
 */

// Default rule. Credentials remain valid for 5 minutes after they've been obtained.
// An acquired credential is shared by all clients.
#define kSJBXRuleDefault                         "default"

// Allow anyone.
#define kSJBXRuleAllow                           "allow"

// Authenticate as an administrator.
#define kSJBXRuleAuthenticateAdmin               "authenticate-admin"

// Like the default rule, but credentials remain valid for only 30 seconds after they've been obtained.
// An acquired credential is shared by all clients.
#define kSJBXRuleAuthenticateAdmin30        	    "authenticate-admin-30"

// Authenticate as a developer.
#define kSJBXRuleAuthenticateDeveloper           "authenticate-developer"

// Authenticate as the session owner.
#define kSJBXRuleAuthenticateSessionOwner        "authenticate-session-owner"

// Authenticate either as the owner or as an administrator.
#define kSJBXRuleAuthenticateSessionOwnerOrAdmin "authenticate-session-owner-or-admin"

// Same as authenticate-session-owner.
#define kSJBXRuleAuthenticateSessionUser         "authenticate-session-user"

// Verify that the user asking for authorization is an administrator.
#define kSJBXRuleIsAdmin                         "is-admin"

// Verify that the user asking for authorization is a developer.
#define kSJBXRuleIsDeveloper                     "is-developer"

// Verify that the process that created this AuthorizationRef is running as root.
#define kSJBXRuleIsRoot                          "is-root"

// Verify that the requesting process is running as the session owner.
#define kSJBXRuleIsSessionOwner                  "is-session-owner"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Request/Response Keys

// Standard keys for the request dictionary

/*!
 @define         kSJBXCommandKey
 
 @abstract       Key for the command string within the request dictionary.
 
 @discussion     Within a request, this key must reference a string that is the name of the
 command to execute.  This must match one of the commands in the
 SJBXCommandSpec array.
 
 The length of a command name must not be greater than 1024 UTF-16 values.
 */

#define kSJBXCommandKey      "com.apple.dts.BetterAuthorizationSample.command"			// CFString

// Standard keys for the response dictionary

/*!
 @define         kSJBXErrorKey
 
 @abstract       Key for the error result within the response dictionary.
 
 @discussion     Within a response, this key must reference a number that is the error result
 for the response, interpreted as an OSStatus.
 */

#define kSJBXErrorKey         "com.apple.dts.BetterAuthorizationSample.error"				// CFDictionary

#define kSJBXErrorDomainKey   "com.apple.dts.BetterAuthorizationSample.error.domain"		// CFString
#define kSJBXErrorCodeKey     "com.apple.dts.BetterAuthorizationSample.error.code"			// CFNumber
#define kSJBXErrorUserInfoKey "com.apple.dts.BetterAuthorizationSample.error.userInfo"		// CFDictionary

/////////////////////////////////////////////////////////////////
#pragma mark ***** Helper Tool Routines

/*!
 @functiongroup  Helper Tool Routines
 */

/*!
 @typedef        SJBXCommandProc
 
 @abstract       Command processing callback.
 
 @discussion     When your helper tool calls SJBXHelperToolMain, it passes in a pointer to an
 array of callback functions of this type.  When SJBXHelperToolMain receives a
 valid command, it calls one of these function so that your program-specific
 code can process the request.  SJBX guarantees that the effective, save and
 real user IDs (EUID, SUID, RUID) will all be zero at this point (that is,
 you're "running as root").
 
 By the time this callback is called, SJBXHelperToolMain has already verified that
 this is a known command.  It also acquires the authorization right associated
 with the command, if any.  However, it does nothing to validate the other
 parameters in the request.  These parameters come from a non-privileged source
 and you should verify them carefully.
 
 Your implementation should get any input parameters from the request and place
 any output parameters in the response.  It can also put an array of file
 descriptors into the response using the kSJBXDescriptorArrayKey key.
 
 If an error occurs, you should just return an appropriate error code.
 SJBXHelperToolMain will ensure that this gets placed in the response.
 
 You should attempt to fail before adding any file descriptors to the response,
 or remove them once you know that you're going to fail.  If you put file
 descriptors into the response and then return an error, those descriptors will
 still be passed back to the client.  It's likely the client isn't expecting this.
 
 Calls to this function will be serialised; that is, once your callback is
 running, SJBXHelperToolMain won't call you again until you return.  Your callback
 should avoid blocking for long periods of time.  If you block for too long, the
 SJBX watchdog will kill the entire helper tool process.
 
 This callback runs in a daemon context; you must avoid doing things that require the
 user's context.  For example, launching a GUI application would be bad.  See
 Technote 2083 "Daemons and Agents" for more information about execution contexts.
 
 @param auth     This is a reference to the authorization instance associated with the original
 application that made the request.
 
 This will never be NULL.
 
 @param userData This is the value from the userData field of the corresponding entry in the
 SJBXCommandSpec array that you passed to SJBXHelperToolMain.
 
 @param request  This dictionary contains the request.  It will have, at a bare minimum, a
 kSJBXCommandKey item whose value matches one of the commands in the
 SJBXCommandSpec array you passed to SJBXHelperToolMain.  It may also have
 other, command-specific parameters.
 
 This will never be NULL.
 
 @param response This is a dictionary into which you can place the response.  It will start out
 empty, and you can add any results you please to it.
 
 If you need to return file descriptors, place them in an array and place that
 array in the response using the kSJBXDescriptorArrayKey key.
 
 There's no need to set the error result in the response.  SJBXHelperToolMain will
 do that for you.  However, if you do set a value for the kSJBXErrorKey key,
 that value will take precedence; in this case, the function result is ignored.
 
 This will never be NULL.
 
 @param asl      A reference to the ASL client handle for logging.
 
 This may be NULL.  However, ASL handles a NULL input, so you don't need to
 conditionalise your code.
 
 @param aslMsg   A reference to a ASL message template for logging.
 
 This may be NULL.  However, ASL handles a NULL input, so you don't need to
 conditionalise your code.
 */

typedef bool (*SJBXCommandProc)(
AuthorizationRef			auth,
const void *                userData,
CFDictionaryRef				request,
CFMutableDictionaryRef      response,
CFErrorRef *				error
);

/*!
 @function       SJBXHelperToolMain
 
 @abstract       Entry point for a privileged helper tool.
 
 @discussion     You should call this function from the main function of your helper tool.  It takes
 care of all of the details of receiving and processing commands.  It will call you
 back (via one of the commandProcs callbacks) when a valid request arrives.
 
 This function assumes acts like a replacement for main.  Thus, it assumes that
 it owns various process-wide resources (like SIGALRM and the disposition of
 SIGPIPE).  You should not use those resources, either in your main function or
 in your callback function.  Also, you should not call this function on a thread,
 or start any other threads in the process.  Finally, this function has a habit of
 exiting the entire process if something goes wrong.  You should not expect the
 function to always return.
 
 This function does not clean up after itself.  When this function returns, you
 are expected to exit.  If the function result is noErr, the command processing
 loop quit in an expected manner (typically because of an idle timeout).  Otherwise
 it quit because of an error.
 
 @param commands An array that describes the commands that you implement, and their associated
 rights.  The array is terminated by a command with a NULL name.  There must be
 at least one valid command.
 
 @param commandProcs
 An array of callback routines that are called when a valid request arrives.  The
 array is expected to perform the operation associated with the corresponding
 command and set up the response values, if any.  The array is terminated by a
 NULL pointer.
 
 IMPORTANT: The array must have exactly the same number of entries as the
 commands array.
 
 @result			An integer representing EXIT_SUCCESS or EXIT_FAILURE.
 */

extern int SJBXHelperToolMain(
                              CFStringRef               helperID,
                              CFStringRef               appID,
                              const SJBXCommandSpec		commands[],
                              const SJBXCommandProc		commandProcs[]
                              );

/////////////////////////////////////////////////////////////////
#pragma mark ***** Application Routines

/*!
 @functiongroup  Application Routines
 */

/*!
 @function       SJBXExecuteRequestInHelperTool
 
 @abstract       Executes a request in the privileged helper tool, returning the response.
 
 @discussion     This routine synchronously executes a request in the privileged helper tool and
 returns the response.
 
 If the function returns an error, the IPC between your application and the helper tool
 failed.  Unfortunately it's not possible to tell whether this failure occurred while
 sending the request or receiving the response, thus it's not possible to know whether
 the privileged operation was done or not.
 
 If the functions returns no error, the IPC between your application and the helper tool
 was successful.  However, the command may still have failed.  You must get the error
 value from the response (typically using SJBXGetErrorFromResponse) to see if the
 command succeeded or not.
 
 On success the response dictionary may contain a value for the kSJBXDescriptorArrayKey key.
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
 a string value for the kSJBXCommandKey.  Furthermore, this string must match
 one of the commands in the array.
 
 The dictionary may also contain other values.  These are passed to the helper
 tool unintepreted.  All values must be serialisable using the CFPropertyList
 API.
 
 This must not be NULL.
 
 @param response This must not be NULL.  On entry, *response must be NULL.  On success, *response
 will not be NULL.  On error, *response will be NULL.
 
 On success, you are responsible for disposing of *response.  You are also
 responsible for closing any descriptors returned in the response.
 
 @result			An OSStatus code (see SJBXErrnoToOSStatus and SJBXOSStatusToErrno).
 */

extern void SJBXExecuteRequestInHelperTool(
                                           AuthorizationRef			auth,
                                           const SJBXCommandSpec	commands[],
                                           CFStringRef				bundleID,
                                           CFDictionaryRef			request,
                                           void                      (^errorHandler)(CFErrorRef error),
                                           void                      (^replyHandler)(CFDictionaryRef response)
                                           );

/*!
 @enum           SJBXFailCode
 
 @abstract       Indicates why a request failed.
 
 @discussion     If SJBXExecuteRequestInHelperTool fails with an error (indicating
 an IPC failure), you can call SJBXDiagnoseFailure to determine what
 went wrong.  SJBXDiagnoseFailure will return the value of this
 type that best describes the failure.
 
 @constant kSJBXFailUnknown
 Indicates that SJBXDiagnoseFailure could not accurately determine the cause of the
 failure.
 
 @constant kSJBXFailDisabled
 The request failed because the helper tool is installed but disabled.
 
 @constant kSJBXFailPartiallyInstalled
 The request failed because the helper tool is only partially installed.
 
 @constant kSJBXFailNotInstalled
 The request failed because the helper tool is not installed at all.
 
 @constant kSJBXFailNeedsUpdate
 The request failed because the helper tool is installed but out of date.
 SJBXDiagnoseFailure will never return this value.  However, if you detect that
 the helper tool is out of date (typically by sending it a "get version" request)
 you can pass this value to SJBXFixFailure to force it to update the tool.
 */

enum {
    kSJBXFailUnknown,
    kSJBXFailDisabled,
    kSJBXFailPartiallyInstalled,
    kSJBXFailNotInstalled,
    kSJBXFailNeedsUpdate
};
typedef uint32_t SJBXFailCode;

/*!
 @function       SJBXDiagnoseFailure
 
 @abstract       Determines the cause of a failed request.
 
 @discussion     If SJBXExecuteRequestInHelperTool fails with an error (indicating an
 IPC failure), you can call this routine to determine what went wrong.
 It returns a SJBXFailCode value indicating the cause of the failure.
 You should use this value to tell the user what's going on and what
 you intend to do about it.  Once you get the user's consent, you can
 call SJBXFixFailure to fix the problem.
 
 For example, if this function result is kSJBXFailDisabled, you could put up the
 dialog saying:
 
 My privileged helper tool is disabled.  Would you like to enable it?
 This operation may require you to authorize as an admin user.
 [Cancel] [[Enable]]
 
 On the other hand, if this function result is kSJBXFailNotInstalled, the dialog might be:
 
 My privileged helper tool is not installed.  Would you like to install it?
 This operation may require you to authorize as an admin user.
 [Cancel] [[Install]]
 
 SJBXDiagnoseFailure will never return kSJBXFailNeedsUpdate.  It's your responsibility
 to detect version conflicts (a good way to do this is by sending a "get version" request
 to the helper tool).  However, once you've detected a version conflict, you can pass
 kSJBXFailNeedsUpdate to SJBXFixFailure to get it to install the latest version of your
 helper tool.
 
 If you call this routine when everything is working properly, you're likely to get
 a result of kSJBXFailUnknown.
 
 @param auth     A reference to your program's authorization instance; you typically get this
 by calling AuthorizationCreate.
 
 This must not be NULL.
 
 @param bundleID The bundle identifier for your program.
 
 This must not be NULL.
 
 @result         A SJBXFailCode value indicating the cause of the failure.  This will never be
 kSJBXFailNeedsUpdate.
 */

extern SJBXFailCode SJBXDiagnoseFailure(
                                      AuthorizationRef			auth,
                                      CFStringRef					bundleID
                                      );

/////////////////////////////////////////////////////////////////
#pragma mark ***** Utility Routines

/*!
 @functiongroup  Utilities
 */

extern CFStringRef const kSJBXErrorDomainAuthorization;

extern CFErrorRef SJBXCreateCFErrorFromErrno(int errNum);
extern CFErrorRef SJBXCreateCFErrorFromCarbonError(OSStatus err);
extern CFErrorRef SJBXCreateCFErrorFromSecurityError(OSStatus err);

#ifdef __cplusplus
}
#endif

#endif
