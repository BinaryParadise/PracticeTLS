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
    private var sessions: [Int32 : GCDAsyncSocket] = [:]
    var waitMsg: TLSHandshakeMessage?
    public init(_ tls: Bool = false) {
        super.init()
        tlsEnabled = tls
        socket = GCDAsyncSocket(delegate: self, delegateQueue: DispatchQueue.global())
    }
    
    @discardableResult public func start(port: UInt16) -> Self {
        do {
            try socket?.accept(onPort: port)
        } catch {
            LogError(error.localizedDescription)
        }
        print("start")
        return self
    }
    
    @discardableResult public func wait() -> Bool {
        CFRunLoopRun()
        return false
    }
}

extension HTTPServer: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didAcceptNewSocket newSocket: GCDAsyncSocket) {
        LogInfo("\(Thread.current)")
        sessions[newSocket.socket4FD()] = newSocket
        
        if tlsEnabled {
            newSocket.readData(tag: .handshake(.clientHello))
        } else {
            newSocket.readData(tag: .http)
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        let rtag: RWTags = tag == 100 ? .http : .handshake(TLSHandshakeType(rawValue: UInt8(tag)) ?? .clientHello)
        LogDebug("\(rtag) \(Thread.current)")
        switch rtag {
        case .handshake(_):
            let stream = DataStream(data)
            if let byte = stream.readByte(), let type = TLSMessageType(rawValue: byte) {
                switch type {
                case .changeCipherSpec:
                    break
                case .alert:
                    LogError("alert")
                    sock.disconnectAfterReadingAndWriting()
                    break
                case .handeshake:
                    tlsResponse(sock, msg: TLSHandshakeMessage.fromData(data: data))
                case .applicatonData:
                    break
                }
            } else {
                LogError("不符合TLS报文协议")
            }
        case .http:
            httpResponse(sock, data: data)
        default:
            break
        }
    }
    
    func tlsResponse(_ sock: GCDAsyncSocket, msg: TLSHandshakeMessage?) -> Void {
        if let res = msg?.responseMessage() {
            waitMsg = res
            sock.writeData(data: res.dataWithBytes(), tag: RWTags(rawValue: res.handshakeType.rawValue) ?? .http)
        }
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
        sock.writeData(data: response.data(using: .utf8), tag: .http)
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let wtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(wtag)")
        switch wtag {
        case .handshake(let handshakeType):
            if handshakeType == .serverHello {
                tlsResponse(sock, msg: waitMsg)
            } else if handshakeType == .serverHelloDone {
                sock.readData(tag: .handshake(.clientKeyExchange))
            } else {
                sock.readData(tag: wtag)
            }
        case .http:
            break
        }
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        if let err = err {
            LogError("\(err)")
        }
        sessions.removeValue(forKey: sock.socket4FD())
    }
}
