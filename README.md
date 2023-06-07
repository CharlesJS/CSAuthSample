#  CSAuthSample

This is a set of libraries that will assist in writing privileged helper tools for macOS applications.
It is intended to be a little more up to date and easier to use than Apple's aging [EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html).
[Pacifist](https://www.charlessoft.com) has been using it for some time.

CSAuthSample began as a port of Nathan de Vries’ [SMJobBlessXPC](https://github.com/atnan/SMJobBlessXPC), although it has been rewritten so many times that I doubt any of the original code remains.
At some point it was rewritten around Apple’s [BetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/BetterAuthorizationSample/Introduction/Intro.html).
More recently it has been rewritten around Apple's [EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html).
This latest rewrite uses NSXPCConnection, and thus requires the helper to be written in either Objective-C or Swift.
For users that require the helper to be in straight C, the older code using libxpc is available in the 'c-helper' branch.

The current code assumes the front-end application will be written in Swift.
Either Objective-C or Swift can be used to write the helper tool.
If you wish to use Swift for the full stack, a Swift package is available.
For your convenience, there is an example app project included that will show you how to write a Swift-based helper app and corresponding client app.

For those who like to be on the cutting edge, a Swift-only rewrite which uses Swift Concurrency is available under the `swift-concurrency` branch.

CSAuthSample is free to use under the terms of the MIT license.

Enjoy!
