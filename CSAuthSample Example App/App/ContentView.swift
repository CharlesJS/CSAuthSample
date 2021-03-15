//
//  ContentView.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import SwiftUI

struct ContentView: View {
    @State private var response = ""

    var body: some View {
        VStack {
            Button {
                MessageSender.shared.sayHello {
                    switch $0 {
                    case .success(let reply):
                        self.response = "Received reply from helper:\n\n\(reply)"
                    case .failure(let error):
                        self.response = "Received error from helper:\n\n\(error.localizedDescription)"
                    }
                }
            } label: {
                Text("Say Hello")
            }.padding()
            Text("Response:")
            Text($response.wrappedValue)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }.padding().frame(minWidth: 300)
    }
}
