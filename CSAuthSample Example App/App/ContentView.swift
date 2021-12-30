//
//  ContentView.swift
//  CSAuthSample Example App
//
//  Created by Charles Srstka on 4/5/20.
//

import SwiftUI

struct ContentView: View {
    @State private var response = ""
    @State private var messageSendInProgress = false

    var body: some View {
        VStack {
            Button {
                Task {
                    do {
                        let reply = try await MessageSender.shared.sayHello()

                        self.response = "Received reply from helper:\n\n\(reply)"
                    } catch {
                        self.response = "Received error from helper:\n\n\(error.localizedDescription)"
                    }
                }
            } label: {
                Text("Say Hello")
            }.padding().disabled(self.messageSendInProgress)
            Button {
                Task {
                    do {
                        let fd = try await MessageSender.shared.openSudoLectureFile()
                        let handle = FileHandle(fileDescriptor: fd.fileDescriptor, closeOnDealloc: false)
                        defer { _ = try? handle.close() }

                        guard let data = try handle.readToEnd() else {
                            throw CocoaError(.fileReadUnknown)
                        }

                        guard let lecture = String(data: data, encoding: .utf8) else {
                            throw CocoaError(.fileReadInapplicableStringEncoding)
                        }

                        self.response = "Read sudo lecture file:\n\n\(lecture)"
                    } catch {
                        self.response = "Received error:\n\n\(error.localizedDescription)"
                    }
                }
            } label: {
                Text("Open sudo lecture file")
            }.padding().disabled(self.messageSendInProgress)
            Button {
                Task {
                    do {
                        let reply = try await MessageSender.shared.getVersion()

                        self.response = "Received reply from helper:\n\n\(reply)"
                    } catch {
                        self.response = "Received error from helper:\n\n\(error.localizedDescription)"
                    }
                }
            } label: {
                Text("Get Helper Version")
            }.padding().disabled(self.messageSendInProgress)
            Button {
                Task {
                    do {
                        let reply = try await MessageSender.shared.uninstallHelperTool()
                        self.response = "Received reply from helper:\n\n\(reply)"
                    } catch {
                        self.response = "Received error \(error.localizedDescription)\n\n"
                    }
                }
            } label: {
                Text("Uninstall")
            }.padding().disabled(self.messageSendInProgress)
            Text("Response:")
            Text($response.wrappedValue)
                .frame(maxWidth: .infinity, minHeight: 300, maxHeight: .infinity)
        }.padding()
    }
}
