//
//  HTTPServer.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation
import CocoaAsyncSocket
import PracticeTLS

public class HTTPServer: NSObject {
    var socket: GCDAsyncSocket?
    var terminated = false
    var tlsEnabled: Bool = false
    public init(_ identity: PEMFileIdentity? = nil) {
        super.init()
        tlsEnabled = identity != nil
        TLSSessionManager.shared.identity = identity
        TLSSessionManager.shared.delegate = self
        socket = GCDAsyncSocket(delegate: self, delegateQueue: DispatchQueue.global())
        socket?.isIPv6Enabled = false
    }
    
    @discardableResult public func start(port: UInt16) -> Self {
        do {
            try socket?.accept(onPort: port)
        } catch {
            LogError(error.localizedDescription)
        }
        print("start on:\(port)")
        return self
    }
    
    @discardableResult public func wait() -> Bool {
        CFRunLoopRun()
        return false
    }
}

extension HTTPServer: TLSConnectionDelegate {
    public func onReceive(application data: [UInt8], userInfo: [String : AnyHashable]) -> [UInt8]? {
        let request = String(bytes: data, encoding: .utf8) ?? ""
        let content = """
            <!DOCTYPE html>
            <html lang="en">
            <title>Practice TLS</title>
            <meta charset="utf-8">
            <body>
            <pre>
            Date: \(Date())
            \(userInfo)
            
            Your Request:
            \(request)
            
            </pre>
            </body></html>
            """
        
//        if content.contains(string: "Connection: Close") {
//            clientWantsMeToCloseTheConnection = true
//        }
        
        let response = """
            HTTP/1.1 200 OK
            Content-Length: \(content.bytes.count)
            Connection: keep-alive
            Content-Type: text/html; charset=utf-8
            Server: PracticeTLS
            """
            .replacingOccurrences(of: "\n", with: "\r\n")
            .appending("\r\n\r\n")
            .appending(content)
        LogInfo(response)
        return Array(response.bytes)
    }
}

extension HTTPServer: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didAcceptNewSocket newSocket: GCDAsyncSocket) {
        LogInfo("")
        if tlsEnabled {
            TLSSessionManager.shared.acceptConnection(newSocket)
        } else {
            newSocket.readData(withTimeout: 5, tag: 0)
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
            .replacingOccurrences(of: "\n", with: "\r\n")
            .appending("\r\n\r\n")
        if let request = String(data: data, encoding: .utf8) {
            if request.contains(string: "Upgrade-Insecure-Requests") {
                //response += "Content-Security-Policy: upgrade-insecure-requests\n"
            }
            LogInfo(request)
        }
        response += """
            \(content)
            """
        sock.write(response.data(using: .utf8) ?? Data(), withTimeout: 5, tag: 0)
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        LogInfo("\(err)")
    }
}
