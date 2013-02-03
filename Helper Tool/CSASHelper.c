/*
 
    File: CSASHelper.c
Abstract: A helper tool that doesn't do anything event remotely interesting.
See the ssd sample for how to use GCD and launchd to set up an on-demand
server via sockets.
 Version: 1.2

Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple
Inc. ("Apple") in consideration of your agreement to the following
terms, and your use, installation, modification or redistribution of
this Apple software constitutes acceptance of these terms.  If you do
not agree with these terms, please do not use, install, modify or
redistribute this Apple software.

In consideration of your agreement to abide by the following terms, and
subject to these terms, Apple grants you a personal, non-exclusive
license, under Apple's copyrights in this original Apple software (the
"Apple Software"), to use, reproduce, modify and redistribute the Apple
Software, with or without modifications, in source and/or binary forms;
provided that if you redistribute the Apple Software in its entirety and
without modifications, you must retain this notice and the following
text and disclaimers in all such redistributions of the Apple Software.
Neither the name, trademarks, service marks or logos of Apple Inc. may
be used to endorse or promote products derived from the Apple Software
without specific prior written permission from Apple.  Except as
expressly stated in this notice, no other rights or licenses, express or
implied, are granted by Apple herein, including but not limited to any
patent rights that may be infringed by your derivative works or by other
works in which the Apple Software may be incorporated.

The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.

IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Copyright (C) 2011 Apple Inc. All Rights Reserved.


*/

#include <CoreFoundation/CoreFoundation.h>
#include "SampleCommon.h"
#include "CSAuthSampleHelperLib.h"
#include <sys/stat.h>

/////////////////////////////////////////////////////////////////
#pragma mark ***** Get Version Command

static bool DoGetVersion(AuthorizationRef authRef, const void *userData, CFDictionaryRef request, CFMutableDictionaryRef response, CFMutableArrayRef descriptorArray, CFErrorRef *error) {
    assert(authRef != NULL);
    assert(response != NULL);
    
    long long version = (long long)kCSASHelperVersion;
    CFNumberRef versionRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberLongLongType, &version);

    CFDictionaryAddValue(response, CFSTR(kSampleGetVersionResponse), versionRef);

    CFRelease(versionRef);
    
    return true;
}

/////////////////////////////////////////////////////////////////
#pragma mark ***** Get Version Command

static bool DoSecretSpyStuff(AuthorizationRef authRef, const void *userData, CFDictionaryRef request, CFMutableDictionaryRef response, CFMutableArrayRef descriptorArray, CFErrorRef *error) {
    assert(authRef != NULL);
    assert(response != NULL);
    
    CFDictionarySetValue(response, CFSTR(kSampleSecretSpyStuffResponse), CFSTR("Hello 007"));
    
    return true;
}

static bool CreateDirectoryRecursively(CFURLRef url, CFErrorRef *error) {
    CFURLRef parentURL = CFURLCreateCopyDeletingLastPathComponent(kCFAllocatorDefault, url);
    char path[PATH_MAX];
    bool success = true;
    
    if (!CFURLResourceIsReachable(parentURL, NULL)) {
        if (!CreateDirectoryRecursively(parentURL, error)) {
            success = false;
        }
    }
    
    if (success) {
        success = CFURLGetFileSystemRepresentation(url, true, (UInt8 *)path, sizeof(path));
    }
    
    if (success) {
        if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
            if (error) *error = CSASCreateCFErrorFromErrno(errno);
            success = false;
        }
    }
    
    CFRelease(parentURL);
    
    return success;
}

static bool DoGetFileDescriptors(AuthorizationRef authRef, const void *userData, CFDictionaryRef request, CFMutableDictionaryRef response, CFMutableArrayRef descriptorArray, CFErrorRef *error) {
    CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("/usr/local/share/CSAuthSample/testfile.txt"), kCFURLPOSIXPathStyle, false);
    CFURLRef parentURL = CFURLCreateCopyDeletingLastPathComponent(kCFAllocatorDefault, fileURL);
    char path[PATH_MAX];
    int fd;
    bool success = true;
    
    assert(authRef != NULL);
    assert(response != NULL);
    assert(descriptorArray != NULL);
    
    if (!CFURLResourceIsReachable(parentURL, NULL)) {
        success = CreateDirectoryRecursively(parentURL, error);
    }
    
    if (success) {
        success = CFURLGetFileSystemRepresentation(fileURL, true, (UInt8 *)path, sizeof(path));
    }
    
    if (success) {
        fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        
        if (fd < 0) {
            if (error) *error = CSASCreateCFErrorFromErrno(errno);
            success = false;
        }
    }
    
    if (success) {
        CFNumberRef fdNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &fd);
        
        CFArrayAppendValue(descriptorArray, fdNum);
        
        CFRelease(fdNum);
    }
    
    CFRelease(parentURL);
    CFRelease(fileURL);
    
    return success;
}

/////////////////////////////////////////////////////////////////
#pragma mark ***** Tool Infrastructure

/*
 IMPORTANT
 ---------
 This array must be exactly parallel to the kSampleCommandSet array
 in "SampleCommon.c".
 */

static const CSASCommandProc kSampleCommandProcs[] = {
    DoGetVersion,
    DoSecretSpyStuff,
    DoGetFileDescriptors,
    NULL
};

int main(int argc, const char *argv[]) {
    // Go directly into CSAuthSampleHelperLib code.
	
    return CSASHelperToolMain(argc, argv, CFSTR(kSampleHelperID), kSampleCommandSet, kSampleCommandProcs, kSampleTimeoutInterval);
}

