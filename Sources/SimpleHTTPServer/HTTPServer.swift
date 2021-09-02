//
//  HTTPServer.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation
import CocoaAsyncSocket
import PracticeTLS

enum RWTags {
    case http1_1
    case magic
    case frame(H2.FrameType)
    
    init(rawValue: UInt8) {
        if rawValue == 255 {
            self = .magic
        } else if rawValue == 110 {
            self = .http1_1
        } else {
            self = .frame(H2.FrameType(rawValue: rawValue)!)
        }
    }
    
    var rawValue: Int {
        switch self {
        case .http1_1:
            return 110
        case .magic:
            return 255
        case .frame(let t):
        return Int(t.rawValue)
        }
    }
}

public class HTTPServer: NSObject {
    var socket: GCDAsyncSocket?
    var terminated = false
    var tlsEnabled: Bool = false
    var nextFrame: H2.Frame?
    
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
    
    func index(_ connection: TLSConnection, requestHeaders: String, h2: Bool = false) -> String {
        let content = """
        <!DOCTYPE html>
        <html lang="en">
        <title>Practice TLS</title>
        <meta charset="utf-8">
        <body>
        <pre>
        Date: \(Date())
        Connection from: \(connection.sock.connectedHost ?? "")
        TLS Version: \(connection.version.description)
        Cipher Suite: \(connection.cipherSuite)
        
        Your Request:
        \(requestHeaders)
        
        </pre>
        </body></html>
        """
        
        if h2 {
            return content
        }
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
        return response
    }
}

extension HTTPServer: TLSConnectionDelegate {
    
    public func didHandshakeFinished(_ connection: TLSConnection) {
        if connection.isHTTP2Enabled {
            nextFrame = H2.FrameWindowUpdate()
            connection.write(H2.FrameSettings().rawBytes(), tag: .frame(.SETTINGS))
        } else {
            connection.read(tag: .http1_1)
        }
    }
    
    public func didWriteApplication(_ connection: TLSConnection, tag: Int) {
        let wtag = RWTags(rawValue: UInt8(tag))
        LogInfo("\(wtag)")
        switch wtag {
        case .http1_1:
            break
        case .magic:
            nextFrame = H2.FrameWindowUpdate()
            connection.writeApplication(data: H2.FrameSettings().rawBytes(), tag: RWTags.frame(.SETTINGS).rawValue)
        case .frame(let type):
            if let frame = nextFrame {
                nextFrame = frame.nextFrame
                connection.write(frame.rawBytes(), tag: .frame(frame.type))
            } else {
                if type == .WINDOW_UPDATE {
                    connection.read(tag: .magic)
                }
            }
            break
        }
    }
    
    public func didReadApplication(_ data: [UInt8], connection: TLSConnection, tag: Int) {
        let rtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(rtag)")
        switch rtag {
        case .http1_1:
            connection.write(index(connection, requestHeaders: String(data: Data(data) , encoding: .utf8)!).data(using: .utf8)!.bytes, tag: .http1_1)
            break
        case .magic:
            let request = String(bytes: data, encoding: .utf8) ?? ""
            let headers = request.components(separatedBy: "\r\n\r\n").first!.split(separator: "\r\n")
            let pri = headers.first?.appending("") ?? ""
            if pri.contains(string: "HTTP/2.0") {
                connection.read(tag: .frame(.SETTINGS))
            }
        case .frame(let type):
            if let f = H2.Frame.fromData(data: data) {
                switch f {
                case is H2.FrameSettings:
                    let fs = f as! H2.FrameSettings
                    if fs.flags.contains(.ack) {
                        let content = index(connection, requestHeaders: "请求", h2: true)
                        
                        let dataFrame = H2.FrameData(application: content.bytes)
                        dataFrame.streamIdentifier = 1
                        
                        let resHead = H2.FrameHeaders(content.bytes.count, contentType: "text/html")
                        resHead.nextFrame = dataFrame
                        resHead.streamIdentifier = 1
                        nextFrame = resHead
                        
                        let fs = H2.FrameSettings()
                        fs.flags = [.ack]
                        fs.payload = []
                        connection.write(fs.rawBytes(), tag: .frame(.SETTINGS))
                    } else {
                        connection.read(tag: .frame(.WINDOW_UPDATE))
                    }
                case is H2.FrameWindowUpdate:
                    connection.read(tag: .frame(.HEADERS))
                case is H2.FrameHeaders:
                    let head = f as! H2.FrameHeaders
                    if head.path == "/" {
                        connection.read(tag: .frame(.SETTINGS))
                    }
                case is H2.FrameGoaway:
                    let goaway = f as! H2.FrameGoaway
                    LogError("\(goaway.additionalDebugData.toString())")
                default:
                    break
                }
            } else {
                LogError("未识别len -> \(data.count)")
            }
        }
    }
}

extension HTTPServer: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didAcceptNewSocket newSocket: GCDAsyncSocket) {
        LogInfo("")
        if tlsEnabled {
            TLSSessionManager.shared.acceptConnection(newSocket)
        } else {
            newSocket.readData(withTimeout: -1, tag: 0)
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

extension TLSConnection {
    func read(tag: RWTags) {
        readApplication(tag: tag.rawValue)
    }
    
    func write(_ data: [UInt8], tag: RWTags) {
        writeApplication(data: data, tag: tag.rawValue)
    }
}
