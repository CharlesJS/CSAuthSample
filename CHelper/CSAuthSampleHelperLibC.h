// CSAuthSampleHelperLib.h
// Copyright Charles Srstka, 2013-2018.
// Based on "BetterAuthorizationSampleLib.h" by Apple Computer.

#ifndef CSAuthSampleHelperLib_h
#define CSAuthSampleHelperLib_h

#include "CSAuthSampleCommonLibC.h"
#include <CoreFoundation/CoreFoundation.h>

/*!
 
 This is the key for the localized authorization prompt strings in the helper's Info.plist.
 
 */

#define kCSASAuthorizationPromptsKey "CSASAuthorizationPrompts"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Helper Tool Routines

/*!
 @functiongroup  Helper Tool Routines
 */

typedef struct CSASCallerCredentials {
    pid_t processID;
    uid_t userID;
    gid_t groupID;
    au_asid_t auditSessionID;
} CSASCallerCredentials;

typedef bool (^CSASConnectionHandler)(
                                      CFDictionaryRef       	request,
                                      CFMutableDictionaryRef	response,
                                      CFMutableArrayRef			fileDescriptors,
                                      CFErrorRef *				errorPtr
                                      );

typedef bool (^CSASCommandBlock)(
                                 AuthorizationRef        auth,
                                 CSASCallerCredentials * creds,
                                 CFDictionaryRef         request,
                                 CFMutableDictionaryRef  response,
                                 CFMutableArrayRef       descriptorArray,
                                 CSASConnectionHandler * connectionHandler,
                                 CFErrorRef *            error
                                 );

extern int CSASHelperToolMain(
                              int                       argc,
                              const char *              argv[],
                              CFDictionaryRef           commandSet,
                              unsigned int              timeoutInterval
                              );

extern CFDictionaryRef CSASCommandSpecCreateCopyWithBlock(CFDictionaryRef commandSpec, CSASCommandBlock commandBlock);

extern CFDictionaryRef CSASGetHelperToolInfoPlist(void);

extern void CSASWatchdogEnableAutomaticTermination(void);
extern void CSASWatchdogDisableAutomaticTermination(void);

#endif
