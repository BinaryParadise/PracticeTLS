//
//  HTTPServer.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation
import CoreFoundation
import PracticeTLS
import Socket

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
    var socket: Socket?
    var terminated = false
    var tlsEnabled: Bool = false
    var nextFrame: H2.Frame?
    
    public init(_ identity: PEMFileIdentity? = nil) {
        super.init()
        tlsEnabled = identity != nil
        TLSSessionManager.shared.identity = identity
        TLSSessionManager.shared.delegate = self
        socket = try? Socket.create(family: .inet, type: .stream, proto: .tcp)
    }
    
    @discardableResult public func start(port: UInt16, quic: Bool = false) -> Self {
        do {
            try socket?.listen(on: Int(port))
            print("start tcp on:\(port)")
            DispatchQueue.global().async { [weak self] in
                guard let self = self else { return }
                repeat {
                    if let newSocket = try? self.socket?.acceptClientConnection() {
                        self.socket(didAcceptNewSocket: newSocket)
                    }
                } while !self.terminated
            }
        } catch {
            LogError(error.localizedDescription)
        }
        return self
    }
    
    @discardableResult public func wait() -> Bool {
        CFRunLoopRun()
        terminated = false
        return false
    }
    
    func altSvc() -> String {
        let port = (socket?.listeningPort ?? 0)
        return """
        Alt-Svc: h3=":\(port)"
        """
    }
    
    func index(_ connection: TLSConnection, requestHeaders: String, h2: Bool = false) -> String {
		var insecure = requestHeaders.contains("Upgrade-Insecure-Requests")                		
		if insecure {			
			var response = ["HTTP/1.1 308 Permanent Redirect"]
			response.append("Connection: close")
        	response.append("Content-Length: 0")
			var host = requestHeaders.split(separator: "\r\n").filter { (item) -> Bool in
				return item.hasPrefix("Host:")
			}.first ?? ""		
			response.append("Location: https://\(host.split(separator: " ")[1])/")
        	response.append("Server: PracticeTLS/0.1.0")
        	return response.joined(separator: "\r\n")		
		} else {
			let content = insecure ? "" : """
				<!DOCTYPE html>
				<html lang="en">
				<title>Practice TLS</title>
				<meta charset="utf-8">
				<link rel="stylesheet" href="index.css">
				<body>
				<pre>
				Date: \(Date())
				Connection from: \(connection.connectedHost)
				TLS Version: \(connection.negotiatedProtocolVersion.description)
				Cipher Suite: \(connection.cipherSuite)

				Your Request:
				\(requestHeaders)

				</pre>
				</body></html>
				"""

			if h2 {
				return content
			}
			var response = ["HTTP/1.1 200 OK"]
			response.append("Connection: keep-alive")			
			response.append("Content-Type: text/html; charset=utf-8")
        	response.append("Content-Length: \(content.bytes.count)")
        	response.append("Server: PracticeTLS/0.1.0")
        	return response.joined(separator: "\r\n")
            .appending("\r\n\r\n")
            .appending(content)
		}
    }
    
    func favicon(_ connection: TLSConnection, h2: Bool = false) -> [UInt8] {
        if h2 {
            return []
        }
        let response = """
            HTTP/1.1 404 OK
            Content-Length: \(0)
            Connection: keep-alive
            Content-Type: image/x-icon
            Server: PracticeTLS
            """
            .replacingOccurrences(of: "\n", with: "\r\n")
            .appending("\r\n\r\n").bytes
        return response
    }
    
    func indexCSS(_ connection: TLSConnection, h2: Bool = false) -> String {
        let content = """
        body {
            background-color: #332F2F;
            color: #f013ef;
        }
        """
        
        if h2 {
            return content
        }
        var response = ["HTTP/1.1 200 OK"]
        response.append("Content-Length: \(content.bytes.count)")
        response.append("Connection: keep-alive")
        response.append("Content-Type: text/css; charset=utf-8")
        response.append("Server: PracticeTLS")
        return response.joined(separator: "\r\n")
            .appending("\r\n\r\n")
            .appending(content)
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
            connection.read(tag: .http1_1)
        case .magic:
            nextFrame = H2.FrameWindowUpdate()
            connection.write(H2.FrameSettings().rawBytes(), tag: .frame(.SETTINGS))
        case .frame(let type):
            if let frame = nextFrame {
                nextFrame = frame.nextFrame
                connection.write(frame.rawBytes(), tag: .frame(frame.type))
            } else {
                switch type {
                case .WINDOW_UPDATE:
                    connection.read(tag: .magic)
                case .DATA:
                    connection.read(tag: .frame(.HEADERS))
                default:
                    break
                }
            }
            break
        }
    }
    
    public func didReadApplication(_ data: [UInt8], connection: TLSConnection, tag: Int) {
        let rtag = RWTags(rawValue: UInt8(tag))
        LogInfo("\(rtag)")
        switch rtag {
        case .http1_1:
            let headers = String(data: Data(data) , encoding: .utf8)?.components(separatedBy: "\r\n\r\n").first ?? ""
            let path = headers.split(separator: "\r\n").first?.split(separator: " ")[1] ?? "/"
            LogInfo("GET \(path)")
            if path == "/index.css" {
                connection.write(indexCSS(connection).bytes, tag: .http1_1)
            } else if path == "/" {
                connection.write(index(connection, requestHeaders: headers).bytes, tag: .http1_1)
            } else {
                connection.write(favicon(connection), tag: .http1_1)
            }
        case .magic:
            let request = String(bytes: data, encoding: .utf8) ?? ""
            let headers = request.components(separatedBy: "\r\n\r\n").first!.split(separator: "\r\n")
            let pri = headers.first?.appending("") ?? ""
            if pri.contains("HTTP/2.0") {
                connection.read(tag: .frame(.SETTINGS))
            }
        case .frame(let type):
            if let f = H2.Frame.fromData(data: data) {
                switch f {
                case is H2.FrameSettings:
                    let fs = f as! H2.FrameSettings
                    if fs.flags.contains(.ack) {
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
                        let hstr = head.headers.map { h in
                            "\(h.name): \(h.value)"
                        }.joined(separator: "\n")
                        let content = index(connection, requestHeaders: hstr, h2: true)
                        
                        let dataFrame = H2.FrameData(application: content.bytes)
                        dataFrame.streamIdentifier = head.streamIdentifier
                        
                        let resHead = H2.FrameHeaders(content.bytes.count, contentType: "text/html")
                        resHead.nextFrame = dataFrame
                        resHead.streamIdentifier = head.streamIdentifier
                        nextFrame = resHead
                        
                        connection.read(tag: .frame(.SETTINGS))
                    } else if head.path == "/index.css" {
                        let content = indexCSS(connection, h2: true)
                        
                        let dataFrame = H2.FrameData(application: content.bytes)
                        dataFrame.streamIdentifier = head.streamIdentifier
                        
                        let resHead = H2.FrameHeaders(content.bytes.count, contentType: "text/css")
                        resHead.streamIdentifier = head.streamIdentifier
                        nextFrame = dataFrame
                        connection.write(resHead.rawBytes(), tag: .frame(.HEADERS))
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

extension HTTPServer {
    func socket(didAcceptNewSocket newSocket: Socket) {
        LogInfo("")
        if tlsEnabled {
            TLSSessionManager.shared.acceptConnection(newSocket)
        } else {
            var data = Data()
            try? newSocket.read(into: &data)
            socket(newSocket, didRead: data, withTag: .http1_1)
        }
    }
    
    func socket(_ sock: Socket, didRead data: Data, withTag tag: RWTags) {
        LogDebug("\(tag)")
        httpResponse(sock, data: data)
    }
    
    func httpResponse(_ sock: Socket, data: Data) {
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
            if request.contains("Upgrade-Insecure-Requests") {
                //response += "Content-Security-Policy: upgrade-insecure-requests\n"
            }
            LogInfo(request)
        }
        response += """
            \(content)
            """
        try? sock.write(from: response.data(using: .utf8) ?? Data())
    }
}

extension TLSConnection {
    func read(tag: RWTags) {
        readApplication(tag: tag.rawValue)
    }
    
    func write(_ data: [UInt8]?, tag: RWTags) {
        guard let data = data else { return }
        writeApplication(data: data, tag: tag.rawValue)
    }
}
