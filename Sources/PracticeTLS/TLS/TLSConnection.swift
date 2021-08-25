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
    
    init(_ sock: GCDAsyncSocket) {
        self.sock = sock
        securityParameters = TLSSecurityParameters()
        super.init()
        sock.delegate = self
        
    }
    
    func handshake() {
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
            print("//msg => \(d.count)")
            handshakeData.append(contentsOf: d)
        }
        print("handshakeData => \(handshakeData.count)")
        let transcriptHash = hashAlgorithm.hashFunction(handshakeData.dropLast(0))
        let verifyData = securityParameters.PRF(secret: securityParameters.masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
        return TLSFinished(verifyData)
    }
}

extension TLSConnection: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        let handshakeType = TLSHandshakeType(rawValue: UInt8(tag)) ?? .clientHello
        LogDebug("\(handshakeType)")
        let stream = DataStream(data)
        if let byte = stream.readByte(), let type = TLSMessageType(rawValue: byte) {
            switch type {
            case .changeCipherSpec:
                break
            case .alert:
                if let d = securityParameters.decrypt([UInt8](data[5...]), contentType: type) {
                    if let alert = TLSAlert(stream: DataStream(data[0...4]+d)) {
                        LogError("alert: \(alert.level) -> \(alert.alertType)")
                    }
                }
                break
            case .handeshake:
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
            case .applicatonData:
                break
            }
        } else {
            LogError("不符合TLS报文协议")
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
                if !changeCipher.isClient {
                    nextMessage = finishedMessage()
                }
                sock.writeData(data: msg.dataWithBytes(), tag: .handshake(.finished))
            } else {
                handshakeMessages.append(msg)
                nextMessage = msg.responseMessage()
                sock.writeData(data: msg.dataWithBytes(), tag: .handshake(msg.handshakeType))
            }
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let handshakeType = TLSHandshakeType(rawValue: UInt8(tag)) ?? .clientHello
        LogDebug("\(handshakeType)")
        if let msg = nextMessage {
            tlsResponse(msg)
        } else {
            if handshakeType == .serverHelloDone {
                sock.readData(tag: .handshake(.clientKeyExchange))
            } else {
                sock.readData(tag: .handshake(handshakeType))
            }
        }
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        if let err = err {
            LogError("\(err)")
        }
        TLSSessionManager.shared.sessions.removeValue(forKey: sock.socket4FD())
    }
}
