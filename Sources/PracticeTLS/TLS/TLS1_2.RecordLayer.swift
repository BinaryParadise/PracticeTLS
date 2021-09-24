//
//  TLSRecord1_2.swift
//  
//
//  Created by Rake Yang on 2021/9/13.
//

import Foundation
import CryptoSwift
import CryptoKit

enum TLS1_2 {}

extension TLS1_2 {
    class RecordLayer: TLSRecordProtocol {
        var context: TLSConnection
        var handshaked: Bool = false
        var clientCipherChanged: Bool = false
        var serverCipherChanged: Bool = false
        var s: TLSSecurityParameters!
        var readEncryptionParameters: EncryptionParameters!
        var writeEncryptionParameters: EncryptionParameters!
        
        required init(_ context: TLSConnection) {
            self.context = context
            s = TLSSecurityParameters(context.cipherSuite)
        }
        
        func derivedSecret(_ transcriptHash: [UInt8]?) {
            
        }
                        
        func setPendingSecurityParametersForCipherSuite(_ cipherSuite : CipherSuite) {
            guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptionDictionary[cipherSuite]
                else {
                    fatalError("Unsupported cipher suite \(cipherSuite)")
            }
            let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
            
            s.bulkCipherAlgorithm = cipherAlgorithm
            s.blockCipherMode     = cipherSuiteDescriptor.blockCipherMode
            s.cipherType          = cipherSuiteDescriptor.cipherType
            s.encodeKeyLength     = cipherAlgorithm.keySize
            s.blockLength         = cipherAlgorithm.blockSize
            s.fixedIVLength       = cipherSuiteDescriptor.fixedIVLength
            s.recordIVLength      = cipherSuiteDescriptor.recordIVLength
            s.authTagSize = cipherSuiteDescriptor.authTagSize
            s.preMasterSecret = context.preMasterKey
            do {
                context.keyExchange = try cipherSuiteDescriptor.keyExchangeAlgorithm == .rsa ? .rsa : .ecdha(.init(nil, group: selectedCurve))
            } catch {
                LogError("\(error)")
            }
        }
        
        func didReadMessage(_ msg: TLSMessage, rawData: [UInt8], unpack: Bool = false) throws {
            if unpack || !clientCipherChanged {                
                LogDebug("\(msg.type) -> \(rawData.count)")
            }
            switch msg.type {
            case .changeCipherSpec:
                clientCipherChanged = true
            case .handshake(_):
                if let handshake = msg as? TLSHandshakeMessage {
                    switch handshake.handshakeType {
                    case .finished:
                        let clientFinished = TLSFinished(context.verifyDataForFinishedMessage(isClient: true))
                        s.clientVerifyData = clientFinished.dataWithBytes()
                        let clientVerifyData = try decrypt(handshake.dataWithBytes(), contentType: handshake.contentType) ?? []
                        if clientVerifyData == s.clientVerifyData {
                            context.sock.writeData(data: TLSChangeCipherSpec().dataWithBytes(), tag: .changeCipherSpec)
                            //踩坑：发送给客户端的finish也需要包含在摘要的握手消息中⚠️⚠️⚠️⚠️⚠️
                            context.handshakeMessages.append(clientFinished)
                        } else {
                            //assert(clientVerifyData == s.clientVerifyData, "消息验证失败")
                            LogWarn("let transcriptHash = \(s.clientVerifyData.toHexString()).uint8Array")
                            context.sendMessage(msg: TLSAlert(alert: .decryptError, alertLevel: .fatal))
                        }
                    default:
                        context.sendMessage(msg: handshake.nextMessage)
                    }
                }
            case .alert:
                var alert: TLSAlert?
                if clientCipherChanged {
                    let d = try decrypt([UInt8](rawData[5...]), contentType: .alert)
                    alert = TLSAlert(stream: ([UInt8](rawData[0...4]) + d).stream, context: context)
                } else {
                    alert = TLSAlert(stream: rawData.stream, context: context)
                }
                if let alert = alert {
                    if alert.level == .fatal {
                        context.disconnect()
                    } else {
                        if alert.alertType == .closeNotify {
                            context.sock.disconnectAfterReadingAndWriting()
                        }
                    }
                    LogError("alert: \(alert.level) -> \(alert.alertType)")
                } else {
                    LogError("alert未识别 -> \(rawData.count)")
                }
            case .applicationData:
                let appData = msg as! TLSApplicationData
                let httpData = try decrypt(appData.rawData, contentType: msg.contentType)
                TLSSessionManager.shared.delegate?.didReadApplication(httpData, connection: context, tag: context.readWriteTag)                
            }
        }
        
        func didWriteMessage(_ tag: RWTags) -> RWTags? {
            let sendNext:() -> Bool = { [weak self] in
                if let msg = self?.context.nextMessage {
                    self?.context.sendMessage(msg: msg)
                    return true
                }
                return false
            }
            
            switch tag {
            case .changeCipherSpec:
                serverCipherChanged = true
                s.serverVerifyData = context.verifyDataForFinishedMessage(isClient: false)
                context.sendMessage(msg: TLSFinished(s.serverVerifyData))
            case .handshake(let handshakeType):
                if sendNext() {
                    
                } else {
                    switch handshakeType {
                    case .serverHelloDone:
                        return .handshake(.clientKeyExchange)
                    case .finished:
                        handshaked = true
                        TLSSessionManager.shared.delegate?.didHandshakeFinished(context)
                    default:
                        break
                    }
                }
                break
            case .applicationData:
                if handshaked {
                    TLSSessionManager.shared.delegate?.didWriteApplication(context, tag: context.readWriteTag)
                }
            default:
                break
            }
            return nil
        }
        
        func keyExchange(algorithm: KeyExchangeAlgorithm, preMasterSecret: [UInt8]) {
            s.preMasterSecret = preMasterSecret
            s.masterSecret = P_hash(s.hashAlgorithm.macAlgorithm.hmacFunction, secret: preMasterSecret, seed: [UInt8]("master secret".utf8)+s.clientRandom+s.serverRandom, outputLength: 48)
                
            let hmacSize = s.cipherType == .aead ? 0 : s.hashAlgorithm.macAlgorithm.size
            let numberOfKeyMaterialBytes = 2 * (hmacSize + s.encodeKeyLength + s.fixedIVLength)
            let keyBlock = s.PRF(secret: s.masterSecret, label: TLSKeyExpansionLabel, seed: s.serverRandom + s.clientRandom, outputLength: numberOfKeyMaterialBytes)
            
            var index = 0
            let clientWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
            index += hmacSize
            
            let serverWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
            index += hmacSize
            
            let clientWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
            index += s.encodeKeyLength
            
            let serverWriteKey = [UInt8](keyBlock[index..<index + s.encodeKeyLength])
            index += s.encodeKeyLength
            
            let clientWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
            index += s.fixedIVLength
            
            let serverWriteIV = [UInt8](keyBlock[index..<index + s.fixedIVLength])
            index += s.fixedIVLength
            
            readEncryptionParameters  = EncryptionParameters(hmac: s.hashAlgorithm.macAlgorithm, MACKey: clientWriteMACKey, bulkCipherAlgorithm: s.bulkCipherAlgorithm, blockCipherMode: s.blockCipherMode, bulkKey: clientWriteKey, blockLength: s.blockLength, fixedIVLength: s.fixedIVLength, recordIVLength: s.recordIVLength, fixedIV: clientWriteIV, authTagSize: s.authTagSize)
    
            writeEncryptionParameters = EncryptionParameters(hmac: s.hashAlgorithm.macAlgorithm, MACKey: serverWriteMACKey, bulkCipherAlgorithm: s.bulkCipherAlgorithm, blockCipherMode: s.blockCipherMode, bulkKey: serverWriteKey, blockLength: s.blockLength, fixedIVLength: s.fixedIVLength, recordIVLength: s.recordIVLength, fixedIV: serverWriteIV, authTagSize: s.authTagSize)
        }
        
        public func encrypt(_ data: [UInt8], contentType: ContentType, iv: [UInt8]?) -> [UInt8]? {
            return writeEncryptionParameters.encrypt(data, contentType: contentType, iv: iv)
        }
        
        public func decrypt(_ encryptedData: [UInt8], contentType: ContentType) throws -> [UInt8] {
            return try readEncryptionParameters.decrypt(encryptedData, contentType: contentType)
        }
    }
    
    class EncryptionParameters: Encryptable, Decryptable {
        var hmac : MACAlgorithm
        var bulkCipherAlgorithm : CipherAlgorithm
        var cipherType : CipherType
        var blockCipherMode : BlockCipherMode?
        var MACKey  : [UInt8]
        var bulkKey : [UInt8]
        var blockLength : Int
        var fixedIVLength : Int
        var recordIVLength : Int
        var fixedIV      : [UInt8]
        var authTagSize: Int
        var sequenceNumber : UInt64
        
        init(hmac: MACAlgorithm,
             MACKey: [UInt8],
             bulkCipherAlgorithm: CipherAlgorithm,
             blockCipherMode: BlockCipherMode? = nil,
             bulkKey: [UInt8],
             blockLength: Int,
             fixedIVLength: Int,
             recordIVLength: Int,
             fixedIV: [UInt8],
             sequenceNumber: UInt64 = UInt64(0),
             authTagSize: Int = 0)
        {
            self.hmac = hmac
            self.bulkCipherAlgorithm = bulkCipherAlgorithm
            self.blockCipherMode = blockCipherMode
            
            if let blockCipherMode = self.blockCipherMode {
                switch blockCipherMode {
                case .cbc:
                    self.cipherType = .block
                case .gcm:
                    self.cipherType = .aead
                }
            }
            else {
                self.cipherType = .stream
            }
            
            self.MACKey = MACKey
            self.bulkKey = bulkKey
            self.blockLength = blockLength
            self.fixedIVLength = fixedIVLength
            self.recordIVLength = recordIVLength
            self.fixedIV = fixedIV
            self.sequenceNumber = sequenceNumber
            self.authTagSize = authTagSize
        }
        
        public func calculateMessageMAC(secret: [UInt8], contentType : ContentType, data : [UInt8]) -> [UInt8]?
        {
            let MACHeader = MACHeader(contentType, dataLength: data.count) ?? []
            return calculateMAC(secret: secret, data: MACHeader + data)
        }
        
        public func calculateMAC(secret : [UInt8], data : [UInt8]) -> [UInt8]? {
            return hmac.hmacFunction(secret, data)
        }
        
        func MACHeader(_ contentType: ContentType, dataLength: Int, version: TLSVersion = .V1_2) -> [UInt8]? {
            //LogWarn("\(title) -> sequenceNumber: \(sequenceNumber)")
            var macData: [UInt8] = []
            macData.append(contentsOf: sequenceNumber.bytes)
            macData.append(contentType.rawValue)
            macData.append(contentsOf: version.rawValue.bytes)
            macData.append(contentsOf: UInt16(dataLength).bytes)
            return macData
        }
        
        public func encrypt(_ data: [UInt8], contentType: ContentType, iv: [UInt8]?) -> [UInt8]? {
            //PS: CryptoSwift的padding处理异常导致加解密有问题⚠️⚠️⚠️
            let isAEAD = cipherType == .aead
            let MAC = isAEAD ? [] : calculateMessageMAC(secret: MACKey, contentType: contentType, data: data)!
            let myPlantText = data + MAC
            let recordIV = iv ?? AES.randomIV(recordIVLength)
            let IV = (isAEAD ? fixedIV:[]) + recordIV
            do {
                let macHeader = isAEAD ? MACHeader(contentType, dataLength: myPlantText.count) ?? [] : []
                //启用 CryptoKit
                #if true
                
                let key = SymmetricKey(data: bulkKey)
                if bulkCipherAlgorithm == .chacha20 {
                    let nonce = (0.bytes + sequenceNumber.bytes) ^ fixedIV
                    let sealedBox = try ChaChaPoly.seal(myPlantText, using: key, nonce: .init(data: nonce), authenticating: macHeader)
                    sequenceNumber += 1
                    return sealedBox.ciphertext + sealedBox.tag.bytes
                }
                
                let b = try CryptoKit.AES.GCM.seal(myPlantText, using: key, nonce: .init(data: IV), authenticating: macHeader)
                var cipherText = recordIV+b.ciphertext.bytes+b.tag
                
                #else
                
                let blockMode:BlockMode = blockCipherMode == .cbc ? CBC(iv: IV) : GCM(iv: IV, additionalAuthenticatedData: macHeader)
                let aes = try AES(key: encryption.bulkKey, blockMode: blockMode, padding: blockCipherMode == .cbc ? .pkcs7 : .noPadding)
                var cipherText = try aes.encrypt(myPlantText)
                if let gcm = blockMode as? GCM {
                    cipherText.append(contentsOf: gcm.authenticationTag ?? [])
                }
                cipherText.insert(contentsOf: recordIV, at: 0)
                
                #endif
                
                sequenceNumber += 1
                return cipherText
            } catch {
                fatalError("AES加密：\(error)")
            }
            return nil
        }
        
        public func decrypt(_ encryptedData: [UInt8], contentType: ContentType) throws -> [UInt8] {
            if encryptedData.count < recordIVLength+blockLength {
                fatalError("意外的消息格式")
            }
            let isAEAD = cipherType == .aead
            let IV = (isAEAD ? fixedIV :[]) + [UInt8](encryptedData[0..<recordIVLength])
            
            let cipherText: [UInt8]
            
            var authTag : [UInt8] = []
            if blockCipherMode == .gcm {
                cipherText = [UInt8](encryptedData[recordIVLength..<(encryptedData.count - authTagSize)])
                authTag = [UInt8](encryptedData[(encryptedData.count - authTagSize)..<encryptedData.count])
            } else {
                cipherText = [UInt8](encryptedData[recordIVLength..<encryptedData.count])
            }
            
            let macHeader = isAEAD ? MACHeader(contentType, dataLength: cipherText.count) ?? [] : []
            
            //启用 CryptoKit
            #if true
            
            let key = SymmetricKey(data: bulkKey)
            if bulkCipherAlgorithm == .chacha20 {
                let nonce = (0.bytes + sequenceNumber.bytes) ^ fixedIV
                let decrypted = try ChaChaPoly.open(.init(combined: nonce+encryptedData), using: key, authenticating: macHeader).bytes
                sequenceNumber += 1
                return decrypted
            }
            
            let message = try CryptoKit.AES.GCM.open(.init(combined: IV+cipherText+authTag), using: key, authenticating: macHeader).bytes
            sequenceNumber += 1
            return message
            
            #else
            
            let blockMode: BlockMode = blockCipherMode == .cbc ? CBC(iv: IV) : GCM(iv: IV, authenticationTag: authTag, additionalAuthenticatedData: macHeader)
            let aes = try AES(key: decryption.bulkKey, blockMode: blockMode, padding: blockCipherMode == .cbc ? .pkcs7: .noPadding)
            let message = try aes.decrypt(cipherText)
            if isAEAD {
                if authTag != (blockMode as? GCM)?.authenticationTag {
                    return nil
                }
                decryption.sequenceNumber += 1
                return message
            }
            
            #endif
            let messageLength = message.count - hmac.size
            let messageContent = [UInt8](message[0..<messageLength])
            
            let MAC = isAEAD ? [] : [UInt8](message[messageLength..<messageLength + hmac.size])
            
            let messageMAC = calculateMessageMAC(secret: MACKey, contentType: contentType, data: messageContent)
            if MAC == messageMAC {
                sequenceNumber += 1
                return messageContent
            } else {
                fatalError("Error: MAC doesn't match")
            }
        }
    }
}
