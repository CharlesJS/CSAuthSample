#  CSAuthSample

This is a set of libraries that will assist in writing privileged helper tools for macOS applications.
It is intended to be much more up to date and easier to use than Apple’s aging [EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html).
[Pacifist](https://www.charlessoft.com) has been using (earlier versions of) it for some time.

CSAuthSample began as a fork of Nathan de Vries’ [SMJobBlessXPC](https://github.com/atnan/SMJobBlessXPC), although it has been rewritten so many times that at this point, none of the original code remains.
Over the years it has been rewritten around Apple’s [BetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/BetterAuthorizationSample/Introduction/Intro.html), then around Apple’s [EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html), then ported to Swift in the app-facing library, and then finally rewritten as pure-Swift both on the app and helper sides.
This latest rewrite uses [SwiftyXPC](https://github.com/CharlesJS/SwiftyXPC) instead of `NSXPCConnection`, and makes full use of Swift concurrency rather than the blocks/closures based approach used in older versions.
By avoiding the use of `NSXPCConnection` and other Foundation class, this version also avoids the need for the helper tool to link against Foundation.

CSAuthSample goes a bit farther than the various example codes that it (used to be) based on, offering built-in support for checking the code signatures of remote processes, which is important to keep your application secure.
It also uses the Swift `Encoder` and `Decoder` protocols to encode objects for sending across the wire, meaning that you can easily send any type that conforms to `Codable` as an argument or return value to any function regardless of whether or not the type can be represented in Objective-C.

Since this version uses Swift concurrency, it requires macOS 10.15 or higher.
If you need to target an older version of macOS, the Objective-C / Swift hybrid version is still on the `master` branch.
If you are _really_ a glutton for punishment and want to write the helper in straight C, the (much) older C-based code is still available under the `c-helper` branch.

The current code assumes that you are all-in on Swift and Swift Concurrency, both for the app and the helper tool.
For your convenience, there is an example app project included that will demonstrate how to use CSAuthSample’s basic features.

CSAuthSample is free to use under the terms of the MIT license.

Enjoy!
