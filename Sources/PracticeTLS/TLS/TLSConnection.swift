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
    
    func verifyDataForFinishedMessage(isClient: Bool = false) -> TLSFinished {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        var handshakeData: [UInt8] = []
        for msg in handshakeMessages {
            let d = msg.messageData()
            print("msg => \(d.count)")
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
                LogError("alert")
                sock.disconnectAfterReadingAndWriting()
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
                        if let em = exchange.encryptedMessage {
                            _ = decryptAndVerifyMAC(contentType: em.type, data: em.message)
                            securityParameters.read?.sequenceNumber += 1
                        }
                        handshakeMessages.append(msg)
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
        guard let encryptionParameters = securityParameters.read else { return nil }
        let IV = [UInt8](data[0..<securityParameters.recordIVLength])
        let cipherText = [UInt8](data[securityParameters.recordIVLength...])
        
                            
        assert(IV+cipherText == data)
        let aes = try? CryptoSwift.AES(key: encryptionParameters.bulkKey, blockMode: CBC(iv: IV), padding: .noPadding)
        
        var message: [UInt8]?
        
        do {
            message = try aes?.decrypt(cipherText)
            assert(message!.first == 20)
        } catch {
            LogError("\(error)")
        }
        
        print("let preMasterSecret:[UInt8] = [\(preMasterKey.toHexArray())]")
        print("let masterSecret:[UInt8] = [\(securityParameters.masterSecret.toHexArray())]")
        print("let clientRandom:[UInt8] = [\(securityParameters.clientRandom.toHexArray())]")
        print("let serverRandom:[UInt8] = [\(securityParameters.serverRandom.toHexArray())]")
        print("let bulkKey:[UInt8] = [\(encryptionParameters.bulkKey.toHexArray())]")
        print("let IV:[UInt8] = [\(IV.toHexArray())]")
        
        print("let cipherData:[UInt8] = [\(data.toHexArray())]")
        
        if let message = message {            
            let hmacLength = securityParameters.hmac.size
            var messageLength = message.count - hmacLength
            
            if securityParameters.blockLength > 0 {
                let padding = message.last!
                let paddingLength = Int(padding) + 1
                var paddingIsCorrect = (paddingLength < message.count)
                paddingIsCorrect = paddingIsCorrect && (message[(message.count - paddingLength) ..< message.count].filter({$0 != padding}).count == 0)
                if !paddingIsCorrect {
                    LogError("Error: could not decrypt message")
                    return nil
                }
                messageLength -= paddingLength
            }
            
            let messageContent = [UInt8](message[0..<messageLength])
            
            let MAC = [UInt8](message[messageLength..<messageLength + hmacLength])
            
            let messageMAC = securityParameters.calculateMessageMAC(secret: encryptionParameters.MACKey, contentType: contentType, data: messageContent, isRead: true)
            
            if let messageMAC = messageMAC, MAC == messageMAC {
                return messageContent
            }
            else {
                LogError("Error: MAC doesn't match")
            }
        }
        
        return nil
    }
    
    func finishedMessage() -> TLSHandshakeMessage {
        let encryptedMessage = TLSEncryptedMessage()
        encryptedMessage.version = version
        let s = securityParameters
        if let write = s.write {
            let data = verifyDataForFinishedMessage().dataWithBytes()
            let MAC = s.calculateMessageMAC(secret: write.MACKey, contentType: encryptedMessage.type, data: data, isRead: false)!
            var myPlantText = data + MAC
            let blockLength = s.blockLength
            if blockLength > 0 {
                let paddingLength = blockLength - ((myPlantText.count) % blockLength)
                if paddingLength != 0 {
                    let padding = [UInt8](repeating: UInt8(paddingLength - 1), count: paddingLength)
                    
                    myPlantText.append(contentsOf: padding)
                }
            }
            
            write.sequenceNumber += 1
            let IV = AES.randomIV(s.recordIVLength)
            let aes = try? AES(key: write.bulkKey, blockMode: CBC(iv: IV), padding: .noPadding)
            var cipherText: [UInt8] = []
            if let encrypted = try? aes?.encrypt(myPlantText) {
                cipherText = IV + encrypted
            }
            
            encryptedMessage.message = cipherText
        }
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
