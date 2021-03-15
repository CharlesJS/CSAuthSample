//
//  ExampleCommandSet.swift
//  Example App
//
//  Created by Charles Srstka on 4/5/20.
//  Copyright © 2020 Charles Srstka. All rights reserved.
//

import CSAuthSampleCommon
import Foundation

let exampleCommandSet: CommandSet = {
    let bundle = Bundle.main

    let sayHelloRightName = "com.charlessoft.CSAuthSample-Example.Say-Hello"
    let sayHelloPrompt = bundle.localizedString(forKey: "SayHello", value: nil, table: "Prompts")
    let sayHelloSelector = #selector(HelperToolProtocol.sayHello(authorizationData:message:reply:))

    let rights = [
        AuthorizationRight(
            selector: sayHelloSelector,
            name: sayHelloRightName,
            rule: kAuthorizationRuleAuthenticateAsAdmin,
            prompt: sayHelloPrompt
        )
    ]

    return CommandSet(authorizationRights: rights)
}()
