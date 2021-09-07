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
    var handshakeMessages: [TLSMessage] = []
    public var version: TLSVersion = .V1_2
    public var cipherSuite: CipherSuite = .TLS_RSA_WITH_AES_256_CBC_SHA
    var securityParameters: TLSSecurityParameters
    var maximumRecordSize: Int = 256
    private var http2Enabled = false
    public var isHTTP2Enabled: Bool {
        return http2Enabled
    }
    public var readWriteTag: Int = 0
    
    /// 最后一个包（粘包处理）
    public var lastPacket: Bool = true
    public var handshaked: Bool = false
    var isTLS1_3Enabled: Bool = false
    
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
    
    public func disconnect() {
        sock.disconnectAfterWriting()
    }
    
    public func readApplication(tag: Int) {
        readWriteTag = tag
        if lastPacket {
            //处理粘包，若为最后一个包开始新读取
            sock.readData(tag: .applicationData)
        }
    }
    
    public func writeApplication(data: [UInt8], tag: Int) {
        readWriteTag = tag
        let encryptedData = securityParameters.encrypt(data, contentType: .applicatonData, iv: nil) ?? []
        securityParameters.write?.sequenceNumber += 1
        sendMessage(msg: TLSApplicationData(encryptedData))
    }
    
    public func didReadMessage(_ msg: TLSMessage, rawData: [UInt8]) {
        LogDebug("\(msg.type) -> \(rawData.count)")
        switch msg.type {
        case .changeCipherSpec:
            break
        case .handeshake:
            if let handshake = msg as? TLSHandshakeMessage {
                switch handshake {
                case is TLSClientHello:
                    let clientHello = handshake as! TLSClientHello
                    //PS：TMD这里要完整的，而不是28字节⚠️⚠️⚠️⚠️⚠️
                    securityParameters.clientRandom = clientHello.random.dataWithBytes()
                    handshakeMessages.append(clientHello)
                    sendHandshake(handshake.responseMessage())
                case is TLSClientKeyExchange:
                    let exchange = msg as! TLSClientKeyExchange
                    preMasterKey = exchange.preMasterSecret.preMasterKey
                    setPendingSecurityParametersForCipherSuite(cipherSuite)
                    handshakeMessages.append(handshake)
                case is TLSEncryptedMessage:
                    let encryptedMsg = msg as! TLSEncryptedMessage
                    securityParameters.clientVerifyData = decryptAndVerifyMAC(contentType: encryptedMsg.type, data: encryptedMsg.message) ?? []
                    //print("let cipherData:[UInt8] = [\(em.message.toHexArray())]")
                    //print("\(securityParameters.description)")
                    //大坑：回复给客户端的finish也需要包含在校验的握手消息中⚠️⚠️⚠️⚠️⚠️
                    let clientFinishedMsg = verifyDataForFinishedMessage(isClient: true)
                    //print("let clientVerifyData:[UInt8] = [\(clientFinishedMsg.dataWithBytes().toHexArray())]")
                    handshakeMessages.append(clientFinishedMsg)
                    securityParameters.read?.sequenceNumber += 1
                    sendHandshake(handshake.responseMessage())
                default: break
                }
            }
        case .alert:
            var alert: TLSAlert?
            if handshaked {
                if let d = securityParameters.decrypt([UInt8](rawData[5...]), contentType: .alert) {
                    alert = TLSAlert(stream: ([UInt8](rawData[0...4]) + d).stream)
                }
            } else {
                alert = TLSAlert(stream: rawData.stream)
            }
            if let alert = alert {
                if alert.alertType == .closeNotify {
                    sock.disconnectAfterReadingAndWriting()
                }
                LogError("alert: \(alert.level) -> \(alert.alertType)")
            } else {
                LogError("alert未识别 -> \(rawData.count)")
            }
        case .applicatonData:
            let appData = msg as! TLSApplicationData
            if let httpData = securityParameters.decrypt(appData.encryptedData, contentType: msg.type) {
                securityParameters.read?.sequenceNumber += 1
                TLSSessionManager.shared.delegate?.didReadApplication(httpData, connection: self, tag: readWriteTag)
            }
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
        case is TLSHelloRetryRequest:
            //TODO:要还是不要？
            handshakeMessages.append(msg)
            sock.writeData(data: msg.dataWithBytes(), tag: .handshake(.helloRetryRequest))
        case is TLSServerHello:
            let serverHello = msg as! TLSServerHello
            securityParameters.serverRandom = serverHello.random.dataWithBytes()
            cipherSuite = serverHello.cipherSuite
            serverHello.version = version
            http2Enabled = serverHello.extend(.application_layer_protocol_negotiation) != nil
            
            handshakeMessages.append(msg)
            nextMessage = msg.responseMessage()
            
            isTLS1_3Enabled = serverHello.extend(.supported_versions) != nil
            if isTLS1_3Enabled {
                securityParameters.preMasterSecret = serverHello.client!.keyExchange
                if let exchange = securityParameters.setupExchange() {
                    serverHello.keyExchange(keyExchange: exchange)
                    setPendingSecurityParametersForCipherSuite(cipherSuite)
                }
            }
            
            sock.writeData(data: serverHello.dataWithBytes(), tag: .handshake(.serverHello))
        case is TLSChangeCipherSpec:
            let change = msg as! TLSChangeCipherSpec
            version = change.version
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
                sock.writeData(data: Array(cur), tag: i < page-1 ? .fragment : .applicationData)
            }
        } else {
            sock.writeData(data: data, tag: .applicationData)
        }
    }
}

extension TLSConnection: GCDAsyncSocketDelegate {
    public func socket(_ sock: GCDAsyncSocket, didRead data: Data, withTag tag: Int) {
        //处理粘包
        let stream = DataStream(data)
        while !stream.endOfStream {
            stream.read(count: 3)
            let length = stream.readUInt16() ?? 0
            stream.position -= 5
            let rawData = stream.read(count: UInt16(5 + length)) ?? []
            if let msg = TLSMessage.fromData(data: rawData) {
                if stream.endOfStream {
                    lastPacket = true
                }
                didReadMessage(msg, rawData: rawData)
            } else {
                LogDebug("未识别 -> \(rawData.count)")
            }
        }
    }
    
    public func socket(_ sock: GCDAsyncSocket, didWriteDataWithTag tag: Int) {
        let wtag = RWTags(rawValue: UInt8(tag))
        LogDebug("\(wtag)")
        switch wtag {
        case .changeCipherSpec:
            if isTLS1_3Enabled {
            } else {
                let finishedMessage = finishedMessage()
                sock.writeData(data: finishedMessage.dataWithBytes(), tag: .handshake(.finished))
            }
        case .handshake(let handshakeType):
            if let msg = nextMessage {
                nextMessage = nil
                if isTLS1_3Enabled {
                    let encryptedData = securityParameters.encrypt(msg.dataWithBytes(), contentType: .applicatonData, iv: nil) ?? []
                    securityParameters.write?.sequenceNumber += 1
                    let clientFinishedMsg = verifyDataForFinishedMessage(isClient: true)
                    handshakeMessages.append(clientFinishedMsg)
                    nextMessage = finishedMessage()
                    sendMessage(msg: TLSApplicationData(encryptedData))
                } else {
                    sendHandshake(msg)
                }
            } else {
                switch handshakeType {
                case .helloRetryRequest:
                    sock.readData(tag: .handshake(.clientHello))
                case .serverHelloDone:
                    sock.readData(tag: .handshake(.clientKeyExchange))
                case .finished:
                    handshaked = true
                    TLSSessionManager.shared.delegate?.didHandshakeFinished(self)
                default:
                    sock.readData(tag: .handshake(handshakeType))
                }
            }
            break
        case .alert:
            break
        case .applicationData:
            TLSSessionManager.shared.delegate?.didWriteApplication(self, tag: readWriteTag)
            break
        case .fragment:
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
