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

#ifndef SMJobBlessXPC_test_SMJobBlessXPCHelperLib_h
#define SMJobBlessXPC_test_SMJobBlessXPCHelperLib_h

#include "SMJobBlessXPCCommonLib.h"
#include <CoreFoundation/CoreFoundation.h>

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
                              const SJBXCommandProc		commandProcs[],
                              unsigned int              timeoutInterval
                              );

extern void WatchdogEnableAutomaticTermination();
extern void WatchdogDisableAutomaticTermination();

#endif
