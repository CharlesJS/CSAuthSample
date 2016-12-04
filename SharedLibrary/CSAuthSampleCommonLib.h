// CSAuthSampleCommonLib.h
// Copyright Charles Srstka, 2013-2017.
// Based on "BetterAuthorizationSampleLib.h" by Apple Computer.

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
#pragma mark ***** Command Specification Dictionary Keys

extern const CFStringRef kCSASCommandSpecCommandNameKey;
extern const CFStringRef kCSASCommandSpecRightNameKey;
extern const CFStringRef kCSASCommandSpecRightDefaultRuleKey;
extern const CFStringRef kCSASCommandSpecRightTimeoutInSecondsKey;
extern const CFStringRef kCSASCommandSpecRightCommentKey;
extern const CFStringRef kCSASCommandSpecRightDescriptionKey;
extern const CFStringRef kCSASCommandSpecCodeSigningRequirementKey;
extern const CFStringRef kCSASCommandSpecExecutionBlockKey;

CFDictionaryRef CSASCommandSpecCreate(CFStringRef commandName,
                                      CFStringRef rightName,
                                      CFStringRef rightDefaultRule,
                                      uint64_t    rightTimeoutInSeconds,
                                      CFStringRef rightComment,
                                      CFStringRef rightDescription,
                                      CFStringRef codeSigningRequirement
                                      );

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

#define kCSASCommandKey      "com.charlessoft.CSAuthSample.command"			// CFString

// Standard keys for the response dictionary

#define kCSASErrorKey         "com.charlessoft.CSAuthSample.error"				// CFDictionary

#define kCSASErrorDomainKey   "com.charlessoft.CSAuthSample.error.domain"		// CFString
#define kCSASErrorCodeKey     "com.charlessoft.CSAuthSample.error.code"			// CFNumber
#define kCSASErrorUserInfoKey "com.charlessoft.CSAuthSample.error.userInfo"		// CFDictionary

#define kCSASDescriptorArrayKey "com.charlessoft.CSAuthSample.descriptors"	// CFArray of CFNumber

#define kCSASCanAcceptFurtherInputKey "com.charlessoft.CSAuthSample.canAcceptFurtherInput"

// "GetVersion" gets the version of the helper tool.  This never requires authorization.

#define kCSASGetVersionCommand        "GetVersion"
#define kCSASGetVersionRightName      "com.charlessoft.CSAuthSample.GetVersion"
// request keys (none)
// response keys
#define kCSASGetVersionResponse		  "Version"                   // CFNumber

// "UninstallHelper" uninstalls the helper tool. This never requires authorization.

#define kCSASRemoveHelperCommand      "RemoveHelper"
#define kCSASRemoveHelperRightName    "com.charlessoft.CSAuthSample.RemoveHelper"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Utility Routines

/*!
 @functiongroup  Utilities
 */

// Our very own error domain.
extern const CFStringRef kCSASErrorDomain;

// Possible errors that could be returned with kCSASErrorDomain.

typedef CF_ENUM(unsigned int, CSASError) {
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

extern CFDictionaryRef CSASCreateBuiltInCommandSet();

#ifdef __cplusplus
}
#endif

#endif
