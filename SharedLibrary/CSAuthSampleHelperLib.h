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

#ifndef CSAuthSampleHelperLib_h
#define CSAuthSampleHelperLib_h

#include "CSAuthSampleCommonLib.h"
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

/*!
 @typedef        CSASCommandProc
 
 @abstract       Command processing callback.
 
 @discussion     When your helper tool calls CSASHelperToolMain, it passes in a pointer to an
 array of callback functions of this type.  When CSASHelperToolMain receives a
 valid command, it calls one of these function so that your program-specific
 code can process the request.  CSAS guarantees that the effective, save and
 real user IDs (EUID, SUID, RUID) will all be zero at this point (that is,
 you're "running as root").
 
 By the time this callback is called, CSASHelperToolMain has already verified that
 this is a known command.  It also acquires the authorization right associated
 with the command, if any.  However, it does nothing to validate the other
 parameters in the request.  These parameters come from a non-privileged source
 and you should verify them carefully.
 
 Your implementation should get any input parameters from the request and place
 any output parameters in the response.  It can also put an array of file
 descriptors into the response using the kCSASDescriptorArrayKey key.
 
 If an error occurs, you should just return an appropriate error code.
 CSASHelperToolMain will ensure that this gets placed in the response.
 
 You should attempt to fail before adding any file descriptors to the response,
 or remove them once you know that you're going to fail.  If you put file
 descriptors into the response and then return an error, those descriptors will
 still be passed back to the client.  It's likely the client isn't expecting this.
 
 Calls to this function will be serialised; that is, once your callback is
 running, CSASHelperToolMain won't call you again until you return.  Your callback
 should avoid blocking for long periods of time.  If you block for too long, the
 CSAS watchdog will kill the entire helper tool process.
 
 This callback runs in a daemon context; you must avoid doing things that require the
 user's context.  For example, launching a GUI application would be bad.  See
 Technote 2083 "Daemons and Agents" for more information about execution contexts.
 
 @param auth     This is a reference to the authorization instance associated with the original
 application that made the request.
 
 This will never be NULL.
 
 @param userData This is the value from the userData field of the corresponding entry in the
 CSASCommandSpec array that you passed to CSASHelperToolMain.
 
 @param request  This dictionary contains the request.  It will have, at a bare minimum, a
 kCSASCommandKey item whose value matches one of the commands in the
 CSASCommandSpec array you passed to CSASHelperToolMain.  It may also have
 other, command-specific parameters.
 
 This will never be NULL.
 
 @param response This is a dictionary into which you can place the response.  It will start out
 empty, and you can add any results you please to it.
 
 If you need to return file descriptors, place them in an array and place that
 array in the response using the kCSASDescriptorArrayKey key.
 
 There's no need to set the error result in the response.  CSASHelperToolMain will
 do that for you.  However, if you do set a value for the kCSASErrorKey key,
 that value will take precedence; in this case, the function result is ignored.
 
 This will never be NULL.
 
 @param asl      A reference to the ASL client handle for logging.
 
 This may be NULL.  However, ASL handles a NULL input, so you don't need to
 conditionalise your code.
 
 @param aslMsg   A reference to a ASL message template for logging.
 
 This may be NULL.  However, ASL handles a NULL input, so you don't need to
 conditionalise your code.
 */

typedef bool (^CSASConnectionHandler)(
                                      CFDictionaryRef       	request,
                                      CFMutableDictionaryRef	response,
                                      CFMutableArrayRef			fileDescriptors,
                                      CFErrorRef *				errorPtr
                                      );

typedef bool (*CSASCommandProc)(
                                AuthorizationRef		auth,
                                const void *            userData,
                                CFDictionaryRef			request,
                                CFMutableDictionaryRef  response,
                                CFMutableArrayRef       descriptorArray,
                                CSASConnectionHandler *	connectionHandler,
                                CFErrorRef *			error
                                );

/*!
 @function       CSASHelperToolMain
 
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

extern int CSASHelperToolMain(
                              int                       argc,
                              const char *              argv[],
                              CFStringRef               helperID,
                              const CSASCommandSpec		commands[],
                              const CSASCommandProc		commandProcs[],
                              unsigned int              timeoutInterval
                              );

extern void CSASWatchdogEnableAutomaticTermination();
extern void CSASWatchdogDisableAutomaticTermination();

#endif
