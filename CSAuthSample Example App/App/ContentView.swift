//
//  ContentView.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

// swiftlint:disable multiple_closures_with_trailing_closure

import SwiftUI

struct ContentView: View {
    @State private var response = ""

    var body: some View {
        VStack {
            Button(action: {
                MessageSender.shared.sayHello {
                    switch $0 {
                    case let .success(reply):
                        self.response = "Received reply from helper:\n\n\(reply)"
                    case let .failure(error):
                        self.response = "Received error from helper:\n\n\(error.localizedDescription)"
                    }
                }
            }) {
                Text("Say Hello")
            }.padding()
            Text("Response:")
            Text($response.wrappedValue)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }.padding().frame(minWidth: 300)
    }
}
