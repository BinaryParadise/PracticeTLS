//
//  HTTPServer.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation
import CocoaAsyncSocket

public class HTTPServer: NSObject {
    var socket: GCDAsyncSocket?
    var terminated = false
    var tlsEnabled: Bool = false
    public init(_ tls: Bool = false) {
        super.init()
        tlsEnabled = tls
        socket = GCDAsyncSocket(delegate: self, delegateQueue: DispatchQueue.global())
        socket?.isIPv6Enabled = false
    }
    
    @discardableResult public func start(port: UInt16) -> Self {
        do {
            try socket?.accept(onInterface: "bridge100", port: port)
        } catch {
            LogError(error.localizedDescription)
        }
        print("start \(TLSSessionManager.shared.identity.certificateChain.first?.signatureAlgorithm)")
        return self
    }
    
    @discardableResult public func wait() -> Bool {
        CFRunLoopRun()
        return false
    }
}

extension HTTPServer: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didAcceptNewSocket newSocket: GCDAsyncSocket) {
        LogInfo("")
        
        if tlsEnabled {
            TLSSessionManager.shared.acceptConnection(TLSConnection(newSocket))
        } else {
            newSocket.readData(tag: .http)
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        LogDebug("\(tag)")
        httpResponse(sock, data: data)
    }
    
    func httpResponse(_ sock: GCDAsyncSocket, data: Data) {
        let content = "Hello, world!"
        var response = """
            HTTP/1.1 200 OK
            Accept-Ranges: bytes
            Content-Length: \(content.count)
            Content-Type: text/html; charset=utf-8
            Etag: "qxb5nrks"
            Last-Modified: Wed, 04 Aug 2021 09:14:15 GMT
            Server: Caddy
            Date: Thu, 05 Aug 2021 08:02:28 GMT
            """
        if let request = String(data: data, encoding: .utf8) {
            if request.contains(string: "Upgrade-Insecure-Requests") {
                //response += "Content-Security-Policy: upgrade-insecure-requests\n"
            }
            LogInfo(request)
        }
        response += """

            \(content)
            """
        sock.writeData(data: Array(response.data(using: .utf8) ?? Data()), tag: .http)
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        LogInfo("\(err)")
    }
}
