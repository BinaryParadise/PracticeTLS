//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/13.
//

import Foundation
import CocoaAsyncSocket
import CryptoSwift

let TLSClientFinishedLabel = [UInt8]("client finished".utf8)
let TLSServerFinishedLabel = [UInt8]("server finished".utf8)
let TLSKeyExpansionLabel = [UInt8]("key expansion".utf8)

class TLSConnection: NSObject {
    var sock: GCDAsyncSocket
    var nextMessage: TLSHandshakeMessage?
    var clientRandom: [UInt8] = []
    var serverRandom: [UInt8] = []
    var preMasterKey: [UInt8] = []
    var masterSecret: [UInt8] = []
    var handshakeMessages: [TLSHandshakeMessage] = []
    var version: TLSVersion = .V1_2
    var hashAlgorithm: HashAlgorithm = .sha256
    var cipherSuite: CipherSuite = .TLS_RSA_WITH_AES_256_CBC_SHA
    var securityParameters: TLSSecurityParameters {
        didSet {
            let s = securityParameters
            if let hmac = s.hmac {
                let hmacSize = s.cipherType == .aead ? 0 : hmac.size
                let fixedIVLength = s.fixedIVLength
                let numberOfKeyMaterialBytes = 2 * (hmacSize + s.encodeKeyLength + fixedIVLength)
                let keyBlock = PRF(secret: masterSecret, label: TLSKeyExpansionLabel, seed: serverRandom + clientRandom, outputLength: numberOfKeyMaterialBytes)
                
                var index = 0
                let clientWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
                index += hmacSize
                
                let serverWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
                index += hmacSize
                
                let clientWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
                index += s.encodeKeyLength
                
                let serverWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
                index += s.encodeKeyLength
                
                let clientWriteIV = [UInt8](keyBlock[index..<index + fixedIVLength])
                index += fixedIVLength
                
                let serverWriteIV = [UInt8](keyBlock[index..<index + fixedIVLength])
                index += fixedIVLength
                                
                readEncryptionParameters  = TLSEncryptionParameters(hmac: hmac,
                                                                 MACKey: clientWriteMACKey,
                                                                 bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                                                                 blockCipherMode: s.blockCipherMode!,
                                                                 bulkKey: clientWriteKey,
                                                                 blockLength: s.blockLength,
                                                                 fixedIVLength: s.fixedIVLength,
                                                                 recordIVLength: s.recordIVLength,
                                                                 fixedIV: clientWriteIV)
                
                writeEncryptionParameters = TLSEncryptionParameters(hmac: hmac,
                                                                 MACKey: serverWriteMACKey,
                                                                 bulkCipherAlgorithm: s.bulkCipherAlgorithm!,
                                                                 blockCipherMode: s.blockCipherMode!,
                                                                 bulkKey: serverWriteKey,
                                                                 blockLength: s.blockLength,
                                                                 fixedIVLength: s.fixedIVLength,
                                                                 recordIVLength: s.recordIVLength,
                                                                 fixedIV: serverWriteIV)
            }
        }
    }
    private var readEncryptionParameters: TLSEncryptionParameters?
    private var writeEncryptionParameters: TLSEncryptionParameters?
    
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
        
        let s = TLSSecurityParameters()
        s.bulkCipherAlgorithm = cipherAlgorithm
        s.blockCipherMode     = cipherSuiteDescriptor.blockCipherMode
        s.cipherType          = cipherSuiteDescriptor.cipherType
        s.encodeKeyLength     = cipherAlgorithm.keySize
        s.blockLength         = cipherAlgorithm.blockSize
        s.fixedIVLength       = cipherSuiteDescriptor.fixedIVLength
        s.recordIVLength      = cipherSuiteDescriptor.recordIVLength
        s.hmac                = cipherSuiteDescriptor.hashAlgorithm.macAlgorithm
        self.securityParameters = s
    }
    
    private func calculateMasterSecret() -> [UInt8]
    {
        return PRF(secret: preMasterKey, label: [UInt8]("master secret".utf8), seed: clientRandom + serverRandom, outputLength: 48)
    }
    
    func verifyDataForFinishedMessage(isClient: Bool = false) -> [UInt8] {
        let finishedLabel = isClient ? TLSClientFinishedLabel : TLSServerFinishedLabel
        var handshakeData: [UInt8] = []
        for msg in handshakeMessages {
            handshakeData.append(contentsOf: msg.dataWithBytes())
        }
        let transcriptHash = hashAlgorithm.hashFunction([UInt8](handshakeData.dropLast(0)))
        return PRF(secret: masterSecret, label: finishedLabel, seed: transcriptHash, outputLength: 12)
    }
    
    func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8] {
        return P_hash(hashAlgorithm.macAlgorithm.hmacFunction, secret: secret, seed: label + seed, outputLength: outputLength)
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
                        clientRandom = clientHello.random.randomBytes
                        handshakeMessages.append(msg)
                        tlsResponse(msg.responseMessage())
                    case is TLSClientKeyExchange:
                        let exchange = msg as! TLSClientKeyExchange
                        preMasterKey = exchange.preMasterSecret.preMasterKey
                        masterSecret = calculateMasterSecret()
                        setPendingSecurityParametersForCipherSuite(cipherSuite)
                        if let em = exchange.encryptedMessage {
                            _ = decryptAndVerifyMAC(contentType: em.type, data: em.message)
                            readEncryptionParameters?.sequenceNumber += 1
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
        guard let encryptionParameters = readEncryptionParameters else { return nil }
        let IV : [UInt8]
        let cipherText : [UInt8]

        IV = [UInt8](data[0..<encryptionParameters.recordIVLength])
        cipherText = [UInt8](data[encryptionParameters.recordIVLength..<data.count])
        
        let blockCipher = BlockCipher.decryptionBlockCipher(encryptionParameters.bulkCipherAlgorithm, mode: encryptionParameters.blockCipherMode, key: encryptionParameters.bulkKey)
                
        if let message = blockCipher?.update(data: cipherText, key: encryptionParameters.bulkKey, IV: IV) {
            
            let hmacLength = encryptionParameters.hmac.size
            var messageLength = message.count - hmacLength
            
            if encryptionParameters.blockLength > 0 {
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
            
            let messageMAC = self.calculateMessageMAC(secret: encryptionParameters.MACKey, contentType: contentType, data: messageContent, isRead: true)
            
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
        if let s = writeEncryptionParameters {
            let verifyData = verifyDataForFinishedMessage()
            let MAC = calculateMAC(secret: s.MACKey, data: verifyData, isRead: false)!
            var plainTextRecordData = verifyData + MAC
            let blockLength = s.blockLength
            if s.blockLength > 0 {
                let paddingLength = blockLength - ((plainTextRecordData.count) % blockLength)
                if paddingLength != 0 {
                    let padding = [UInt8](repeating: UInt8(paddingLength - 1), count: paddingLength)
                    
                    plainTextRecordData.append(contentsOf: padding)
                }
            }
            let aes = try? CryptoSwift.AES(key: s.bulkKey, blockMode: CBC(iv: CryptoSwift.AES.randomIV(s.recordIVLength)))
            encryptedMessage.message = (try? aes?.encrypt(plainTextRecordData)) ?? []
        }
        return encryptedMessage
    }
    
    private func calculateMessageMAC(secret: [UInt8], contentType : TLSMessageType, data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        guard let MACHeader = self.MACHeader(forContentType: contentType, dataLength: data.count, isRead: isRead) else { return nil }
        
        return self.calculateMAC(secret: secret, data: MACHeader + data, isRead: isRead)
    }
    
    private func MACHeader(forContentType contentType: TLSMessageType, dataLength: Int, isRead: Bool) -> [UInt8]? {
        var macData: [UInt8] = []
        macData.append(0)
        macData.append(contentType.rawValue)
        macData.append(contentsOf: version.rawValue.bytes())
        macData.append(contentsOf: UInt16(dataLength).bytes())
        
        return macData
    }
    
    private func calculateMAC(secret : [UInt8], data : [UInt8], isRead : Bool) -> [UInt8]? {
        var HMAC : (_ secret : [UInt8], _ data : [UInt8]) -> [UInt8]
        if let algorithm = isRead ? self.readEncryptionParameters?.hmac : self.writeEncryptionParameters?.hmac {
            switch (algorithm)
            {
            case .hmac_md5:
                HMAC = HMAC_MD5
                
            case .hmac_sha1:
                HMAC = HMAC_SHA1
                
            case .hmac_sha256:
                HMAC = HMAC_SHA256
                
            case .hmac_sha384:
                HMAC = HMAC_SHA384
                
            case .hmac_sha512:
                HMAC = HMAC_SHA512
            }
        }
        else {
            return nil
        }
        
        return HMAC(secret, data)
    }
    
    func tlsResponse(_ msg: TLSHandshakeMessage?) -> Void {
        if let msg = msg {
            if msg is TLSServerHello {
                let serverHello = msg as! TLSServerHello
                serverRandom = serverHello.random.randomBytes
                cipherSuite = serverHello.cipherSuite
                setPendingSecurityParametersForCipherSuite(serverHello.cipherSuite)
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
