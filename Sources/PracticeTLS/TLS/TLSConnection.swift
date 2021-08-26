//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/13.
//

import Foundation
import CocoaAsyncSocket
import CryptoSwift

public let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
public let TLSServerFinishedLabel = [UInt8]("server finished".utf8)
public let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

class TLSConnection: NSObject {
    var sock: GCDAsyncSocket
    var nextMessage: TLSHandshakeMessage?
    var preMasterKey: [UInt8] = []
    var handshakeMessages: [TLSHandshakeMessage] = []
    var version: TLSVersion = .V1_2
    var hashAlgorithm: HashAlgorithm = .sha256
    var cipherSuite: CipherSuite?
    var securityParameters: TLSSecurityParameters
    var clientWantsMeToCloseTheConnection = true

    init(_ sock: GCDAsyncSocket) {
        self.sock = sock
        securityParameters = TLSSecurityParameters()
        super.init()
        sock.delegate = self
        
    }
    
    func handshake() {
        LogInfo("handshake start")
        sock.readData(tag: .handshake(.clientHello))
    }
    
    func setPendingSecurityParametersForCipherSuite(_ cipherSuite : CipherSuite) {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptionDictionary[cipherSuite]
            else {
                fatalError("Unsupported cipher suite \(cipherSuite)")
        }
        let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
        
        let s = securityParameters
        s.bulkCipherAlgorithm = cipherAlgorithm
        s.blockCipherMode     = cipherSuiteDescriptor.blockCipherMode
        s.cipherType          = cipherSuiteDescriptor.cipherType
        s.encodeKeyLength     = cipherAlgorithm.keySize
        s.blockLength         = cipherAlgorithm.blockSize
        s.fixedIVLength       = cipherSuiteDescriptor.fixedIVLength
        s.recordIVLength      = cipherSuiteDescriptor.recordIVLength
        s.hmac                = cipherSuiteDescriptor.hashAlgorithm.macAlgorithm
        s.preMasterSecret = preMasterKey
        s.transformParamters()
    }
    
    func verifyDataForFinishedMessage(isClient: Bool) -> TLSFinished {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        var handshakeData: [UInt8] = []
        for msg in handshakeMessages {
            let d = msg.messageData()
            //print("//msg => \(d.count)")
            handshakeData.append(contentsOf: d)
        }
        let transcriptHash = hashAlgorithm.hashFunction(handshakeData.dropLast(0))
        let verifyData = securityParameters.PRF(secret: securityParameters.masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
        return TLSFinished(verifyData)
    }
}

extension TLSConnection: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        let rtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(rtag)")
        switch rtag {
        case .handshake(_):
            let stream = DataStream(data)
            if let msg = TLSHandshakeMessage.fromData(data: data) {
                switch msg {
                case is TLSClientHello:
                    let clientHello = msg as! TLSClientHello
                    //PS：TMD这里要完整的，而不是28字节
                    securityParameters.clientRandom = clientHello.random.dataWithBytes()
                    handshakeMessages.append(msg)
                    tlsResponse(msg.responseMessage())
                case is TLSClientKeyExchange:
                    let exchange = msg as! TLSClientKeyExchange
                    preMasterKey = exchange.preMasterSecret.preMasterKey
                    setPendingSecurityParametersForCipherSuite(cipherSuite!)
                    handshakeMessages.append(msg)
                    
                    if let em = exchange.encryptedMessage {
                        securityParameters.clientVerifyData = decryptAndVerifyMAC(contentType: em.type, data: em.message) ?? []
                        //大坑：客户端的finish也需要包含在校验的握手消息中⚠️⚠️⚠️⚠️⚠️
                        let clientFinishedMsg = verifyDataForFinishedMessage(isClient: true)
                        handshakeMessages.append(clientFinishedMsg)
                        securityParameters.read?.sequenceNumber += 1
                    }
                    tlsResponse(msg.responseMessage())
                default: break
                }
            }
        case .content(let contentType):
            if contentType == .applicatonData {
                if let msg = TLSEncryptedMessage(stream: DataStream(data)) {
                    if let httpData = securityParameters.decrypt(msg.message, contentType: msg.type) {
                        let content = """
                            <!DOCTYPE html>
                            <html lang="en">
                            <title>Swift TLS</title>
                            <meta charset="utf-8">
                            <body>
                            <pre>
                            Date: \(Date())
                            Connection from \(sock.connectedHost ?? "")
                            TLS Version: \(version.description)
                            Cipher: \(cipherSuite!.description)
                            
                            Your Request:
                            \(String(bytes: httpData, encoding: .utf8) ?? "")
                            
                            </pre>
                            </body>
                            </html>
                            """
                        httpsResponse(content)
                    }
                }
            } else if contentType == .alert {
                if let d = securityParameters.decrypt([UInt8](data[5...]), contentType: contentType) {
                    if let alert = TLSAlert(stream: DataStream(data[0...4]+d)) {
                        LogError("alert: \(alert.level) -> \(alert.alertType)")
                    }
                }
            }
            break
        case .http:
            break
        }
    }
    
    private func decryptAndVerifyMAC(contentType : TLSMessageType, data : [UInt8]) -> [UInt8]? {
        return securityParameters.decrypt(data, contentType: contentType)
    }
    
    func finishedMessage() -> TLSHandshakeMessage {
        let encryptedMessage = TLSEncryptedMessage()
        encryptedMessage.version = version
        
        let data = verifyDataForFinishedMessage(isClient: false).dataWithBytes()
        securityParameters.serverVerifyData = data
        let encrypted = securityParameters.encrypt(data, contentType: encryptedMessage.type)
        securityParameters.write?.sequenceNumber += 1
        encryptedMessage.message = encrypted ?? []
        return encryptedMessage
    }
    
    func tlsResponse(_ msg: TLSHandshakeMessage?) -> Void {
        if let msg = msg {
            if msg is TLSServerHello {
                let serverHello = msg as! TLSServerHello
                securityParameters.serverRandom = serverHello.random.dataWithBytes()
                cipherSuite = serverHello.cipherSuite
            }
            if msg is TLSChangeCipherSpec {
                let changeCipher = msg as! TLSChangeCipherSpec
                sock.writeData(data: msg.dataWithBytes(), tag: .content(changeCipher.type))
            } else {
                handshakeMessages.append(msg)
                nextMessage = msg.responseMessage()
                sock.writeData(data: msg.dataWithBytes(), tag: .handshake(msg.handshakeType))
            }
        }
    }
    
    func httpsResponse(_ content: String) {
        
        if content.contains(string: "keep-alive") {
            clientWantsMeToCloseTheConnection = true
        }
        
        var header = """
            HTTP/1.1 200 OK
            Accept-Ranges: bytes
            Content-Length: \(content.count)
            Connection: Close
            Content-Type: text/html; charset=utf-8
            Etag: "\(AES.randomIV(8).toHexString())"
            Last-Modified: Wed, 04 Aug 2021 09:14:15 GMT
            Server: PracticeTLSTool
            Date: Thu, 05 Aug 2021 08:02:28 GMT
            """
            .replacingOccurrences(of: "\n", with: "\r\n")
            + "\r\n\r\n"
        let resData = Array((header+content).data(using: .utf8) ?? Data())
        let encryptedData = securityParameters.encrypt(resData, contentType: .applicatonData, iv: nil) ?? []
        sendMessage(msg: TLSApplicationData(encryptedData))
    }
    
    func sendMessage(msg: TLSMessage) {
        sock.writeData(data: msg.dataWithBytes(), tag: .content(.applicatonData))
        if clientWantsMeToCloseTheConnection {
            //sock.disconnectAfterReadingAndWriting()
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let wtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(wtag)")
        switch wtag {
        case .handshake(let handshakeType):
            if let msg = nextMessage {
                tlsResponse(msg)
            } else {
                if handshakeType == .serverHelloDone {
                    sock.readData(tag: .handshake(.clientKeyExchange))
                } else if handshakeType == .finished {
                    sock.readData(tag: .content(.applicatonData))
                } else {
                    sock.readData(tag: .handshake(handshakeType))
                }
            }
            break
        case .content(let contentType):
            if contentType == .changeCipherSpec {
                let finishedMessage = finishedMessage()
                sock.writeData(data: finishedMessage.dataWithBytes(), tag: .handshake(.finished))
            } else if contentType == .alert {
                
            }
            break
        case .http:
            break
        }
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        LogInfo("\(err)")
        TLSSessionManager.shared.sessions.removeValue(forKey: sock.socket4FD())
    }
}
