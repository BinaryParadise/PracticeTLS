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

public class TLSConnection: NSObject {
    var sessionId: String
    public var sock: GCDAsyncSocket
    var nextMessage: TLSHandshakeMessage?
    var preMasterKey: [UInt8] = []
    var handshakeMessages: [TLSHandshakeMessage] = []
    public var version: TLSVersion = .V1_2
    public var cipherSuite: CipherSuite = .TLS_RSA_WITH_AES_256_CBC_SHA
    var securityParameters: TLSSecurityParameters
    var clientWantsMeToCloseTheConnection = false
    var maximumRecordSize: Int = 256
    private var rwTag: Int = 0
    
    init(_ sock: GCDAsyncSocket) {
        self.sock = sock
        securityParameters = TLSSecurityParameters(cipherSuite)
        sessionId = AES.randomIV(16).toHexString()
        super.init()
        self.sock.delegate = self
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
        let transcriptHash = securityParameters.hashAlgorithm.hashFunction(handshakeData.dropLast(0))
        let verifyData = securityParameters.PRF(secret: securityParameters.masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
        return TLSFinished(verifyData)
    }
    
    public func readApplication(tag: Int) {
        rwTag = tag
        sock.readData(tag: .applicationData)
    }
    
    public func writeApplication(data: [UInt8], tag: Int) {
        rwTag = tag
        let encryptedData = securityParameters.encrypt(data, contentType: .applicatonData, iv: nil) ?? []
        securityParameters.write?.sequenceNumber += 1
        sendMessage(msg: TLSApplicationData(encryptedData))
    }
}

extension TLSConnection: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        let rtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(rtag)")
        switch rtag {
        case .changeCipherSpec:
            break
        case .handshake(_):
            if let msg = TLSHandshakeMessage.fromData(data: data) {
                switch msg {
                case is TLSClientHello:
                    let clientHello = msg as! TLSClientHello
                    if clientHello.cipherSuites.contains(.TLS_RSA_WITH_AES_256_CBC_SHA256) {
                        cipherSuite = .TLS_RSA_WITH_AES_256_CBC_SHA256
                    }
                    //PS：TMD这里要完整的，而不是28字节⚠️⚠️⚠️⚠️⚠️
                    securityParameters.clientRandom = clientHello.random.dataWithBytes()
                    handshakeMessages.append(msg)
                    sendHandshake(msg.responseMessage())
                case is TLSClientKeyExchange:
                    let exchange = msg as! TLSClientKeyExchange
                    preMasterKey = exchange.preMasterSecret.preMasterKey
                    setPendingSecurityParametersForCipherSuite(cipherSuite)
                    handshakeMessages.append(msg)
                    
                    if let em = exchange.encryptedMessage {
                        securityParameters.clientVerifyData = decryptAndVerifyMAC(contentType: em.type, data: em.message) ?? []
                        //print("let cipherData:[UInt8] = [\(em.message.toHexArray())]")
                        //print("\(securityParameters.description)")
                        //大坑：回复给客户端的finish也需要包含在校验的握手消息中⚠️⚠️⚠️⚠️⚠️
                        let clientFinishedMsg = verifyDataForFinishedMessage(isClient: true)
                        //print("let clientVerifyData:[UInt8] = [\(clientFinishedMsg.dataWithBytes().toHexArray())]")
                        handshakeMessages.append(clientFinishedMsg)
                        securityParameters.read?.sequenceNumber += 1
                    }
                    sendHandshake(msg.responseMessage())
                default: break
                }
            }
        case .alert:
            if data.count < securityParameters.recordIVLength {
                if let alert = TLSAlert(stream: DataStream(data)) {
                    LogError("alert: \(alert.level) -> \(alert.alertType)")
                }
            } else if let d = securityParameters.decrypt([UInt8](data[5...]), contentType: .alert) {
                if let alert = TLSAlert(stream: DataStream(data[0...4]+d)) {
                    LogError("alert: \(alert.level) -> \(alert.alertType)")
                }
            }
        case .applicationData:
            if let byte: UInt8 = data.first, let type = TLSMessageType(rawValue: byte), type != .applicatonData {
                socket(sock, didRead: data, withTag: Int(byte))
                break
            }
            if let msg = TLSEncryptedMessage(stream: DataStream(data)) {
                if let httpData = securityParameters.decrypt(msg.message, contentType: msg.type) {
                    securityParameters.read?.sequenceNumber += 1
                    TLSSessionManager.shared.delegate?.didReadApplicaton(httpData, connection: self, tag: rwTag)
                }
            }
        case .custom(_):
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
    
    func sendHandshake(_ msg: TLSHandshakeMessage?) -> Void {
        guard let msg = msg else { return }
        switch msg {
        case is TLSServerHello:
            let serverHello = msg as! TLSServerHello
            //TODO:serverHello.sessionID = sessionId
            securityParameters.serverRandom = serverHello.random.dataWithBytes()
            serverHello.cipherSuite = cipherSuite
            handshakeMessages.append(msg)
            nextMessage = msg.responseMessage()
            sock.writeData(data: serverHello.dataWithBytes(), tag: .handshake(.serverHello))
        case is TLSChangeCipherSpec:
            sock.writeData(data: msg.dataWithBytes(), tag: .changeCipherSpec)
        default:
            handshakeMessages.append(msg)
            nextMessage = msg.responseMessage()
            sock.writeData(data: msg.dataWithBytes(), tag: .handshake(msg.handshakeType))
        }
    }
    
    func sendMessage(msg: TLSMessage) {
        let data = msg.dataWithBytes()
        if maximumRecordSize < data.count {
            let page = (data.count/maximumRecordSize+(data.count%maximumRecordSize > 0 ? 1:0))
            for i in 0..<page {
                let cur = data[i*maximumRecordSize..<min(data.count, (i+1)*maximumRecordSize)]
                sock.writeData(data: Array(cur), tag: i < page-1 ? .custom(255) : .applicationData)
            }
        } else {
            sock.writeData(data: data, tag: .applicationData)
        }
        if clientWantsMeToCloseTheConnection {
            sock.disconnectAfterReadingAndWriting()
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let wtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(wtag)")
        switch wtag {
        case .changeCipherSpec:
            let finishedMessage = finishedMessage()
            sock.writeData(data: finishedMessage.dataWithBytes(), tag: .handshake(.finished))
        case .handshake(let handshakeType):
            if let msg = nextMessage {
                nextMessage = nil
                sendHandshake(msg)
            } else {
                if handshakeType == .serverHelloDone {
                    sock.readData(tag: .handshake(.clientKeyExchange))
                } else if handshakeType == .finished {
                    TLSSessionManager.shared.delegate?.didHandshakeFinished(self)
                } else {
                    sock.readData(tag: .handshake(handshakeType))
                }
            }
            break
        case .alert:
            break
        case .applicationData:
            TLSSessionManager.shared.delegate?.didWriteApplication(self, tag: rwTag)
            sock.readData(tag: .applicationData)
            break
        case .custom(_):
            break
        }
    }
    
    public func socketDidDisconnect(_ sock: GCDAsyncSocket, withError err: Error?) {
        LogInfo("\(err)")
        TLSSessionManager.shared.clearConnection(self)
    }
}
