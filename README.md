#  CSAuthSample

This is a set of libraries that will assist in writing privileged helper tools for macOS applications. It is intended to be a little more up to date and easier to use than Apple's aging [EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html). [Pacifist](https://www.charlessoft.com) has been using it for some time.

CSAuthSample began as a port of Nathan de Vries’ [SMJobBlessXPC](https://github.com/atnan/SMJobBlessXPC), although it has been rewritten so many times that I doubt any of the original code remains. At some point it was rewritten around Apple’s [BetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/BetterAuthorizationSample/Introduction/Intro.html). More recently it has been rewritten around Apple's [EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html). This latest rewrite uses NSXPCConnection, and thus requires the helper to be written in Objective-C. For users that require the helper to be in straight C, the older code using libxpc is available in the 'c-helper' branch.

The current code assumes the front-end application will be written in Swift. Swift is not yet supported on the helper side, because it requires the inclusion of the Swift runtime, which is unreasonably heavyweight for a privileged helper tool. Once Swift's ABI is stabilized, I may update CSAuthSample to support Swift-based helper tools as well.

I hope to include a sample application to better explain how the library is used as soon as time allows.

CSAuthSample is free to use for any purpose, but I would appreciate it if you left an attribution in the documentation.

Enjoy!
