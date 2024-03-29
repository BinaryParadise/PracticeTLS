//
//  TLSRecord1_3.swift
//  
//
//  Created by Rake Yang on 2021/9/13.
//

import Foundation
import Crypto

extension TLS1_3 {
    static let ivLabel  = [UInt8]("iv".utf8)
    static let keyLabel = [UInt8]("key".utf8)
    
    class RecordLayer: TLSRecordProtocol, CustomStringConvertible, CustomDebugStringConvertible {
        var context: TLSConnection
        var handshaked: Bool = false
        var clientCipherChanged: Bool = false
        var serverCipherChanged: Bool = false
        var handshakeState: HandshakeState
        var s: TLSSecurityParameters!
        let sema = DispatchSemaphore(value: 10)
        
        required init(_ context: TLSConnection) {
            self.context = context
            s = TLSSecurityParameters(context.cipherSuite)
            handshakeState = TLS1_3.HandshakeState(s.hashAlgorithm)
        }
        
        func derivedSecret(_ transcriptHash: [UInt8]?) {
            switch context.keyExchange {
            case .rsa:
                break
            case .ecdha(let encryptor):
                s.preMasterSecret = context.preMasterKey
                let shareSecret = try? encryptor.keyExchange(context.preMasterKey)
                s.masterSecret = shareSecret!
                handshakeState.deriveHandshakeSecret(with: shareSecret!, transcriptHash: transcriptHash ?? context.transcriptHash)
                changeReadKey(with: handshakeState.clientHandshakeTrafficSecret!)
                changeWriteKey(with: handshakeState.serverHandshakeTrafficSecret!)
                break
            }
        }
        
        func didReadMessage(_ msg: TLSMessage, rawData: [UInt8], unpack: Bool = false) throws {
            if unpack || !clientCipherChanged {
                LogInfo("\(msg.type) -> \(rawData.count)")
            }
            switch msg.type {
            case .changeCipherSpec:
                clientCipherChanged = true
            case .handshake(_):
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                } else {
                    switch msg {
                    case is TLSFinished:
                        let finished = msg as! TLSFinished
                        if finished.verifyData == finishedData(forClient: true) {
                            handshaked = true
                            
                            //线程步调不一致导致解密失败⚠️⚠️⚠️⚠️
                            //sema.wait()
                            changeReadKey(with: handshakeState.clientTrafficSecret!)
                            if TLSSessionManager.shared.isDebug {
                                try? description.write(toFile: "\(NSHomeDirectory())/MasterSecretKey.log", atomically: true, encoding: .utf8)
                            }
                            TLSSessionManager.shared.delegate?.didHandshakeFinished(context)
                        } else {
                            context.sendMessage(msg: TLSAlert(alert: .badRecordMAC, alertLevel: .fatal))
                        }
                    default:
                        break
                    }
                }
            case .alert:
                if let alert = msg as? TLSAlert {
                    if alert.alertType == .closeNotify {
                        context.disconnect()
                    }
                    LogError("alert: \(alert.level) -> \(alert.alertType)")
                } else {
                    LogError("alert未识别 -> \(rawData.count)")
                }
            case .applicationData:
                do {
                    let appData = msg as! TLSApplicationData
                    let decryptedData = try decrypt(appData.rawData, contentType: msg.contentType)
                    if let contentType = ContentType(rawValue: decryptedData.last ?? 0) {
                        if contentType == .alert {
                            try didReadMessage(TLSAlert(stream: Array(decryptedData[0...1]).stream, context: context)!, rawData: decryptedData, unpack: true)
                            return
                        } else {
                            if handshaked {
                                TLSSessionManager.shared.delegate?.didReadApplication(decryptedData.dropLast(), connection: context, tag: context.readWriteTag)
                            } else {
                                if let newMsg = TLSMessage.fromData(data: decryptedData.dropLast(), context: context, contentType: contentType) {
                                    try didReadMessage(newMsg, rawData: decryptedData.dropLast(), unpack: true)
                                }
                            }
                        }
                    }
                } catch {
                    LogError("\(error) \(decryptor.description)")
                    context.sendMessage(msg: TLSAlert(alert: .badRecordMAC, alertLevel: .fatal))
                }
            }
        }
        
        func didWriteMessage(_ tag: RWTags) -> RWTags? {
            switch tag {
            case .handshake(let handshakeType):
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                } else {
                    switch handshakeType {
                    case .serverHello:
                        derivedSecret(context.transcriptHash)
                        context.sendMessage(msg: TLSEncryptedExtensions(context: context))
                    case .encryptedExtensions:
                        context.sendMessage(msg: TLSCertificate(context))
                    case .certificate:
                        sendCertificateVerify()
                    case .certificateVerify:
                        sendFinished()
                    case .helloRetryRequest:
                        return .handshake(.clientHello)
                    case .finished:
                        return .applicationData
                    default:
                        break
                    }
                }
                break
            case .applicationData:
                if handshaked {
                    TLSSessionManager.shared.delegate?.didWriteApplication(context, tag: context.readWriteTag)
                } else {
                    context.sendMessage(msg: context.nextMessage)
                }
            default:
                break
            }
            return nil
        }
        
        func sendCertificateVerify() {
            if context.negotiatedProtocolVersion == .V1_3 {
                let signer = RSAEncryptor.shared
                
                var proofData = [UInt8](repeating: 0x20, count: 64)
                proofData += TLS1_3.serverCertificateVerifyContext
                proofData += [0]
                proofData += context.transcriptHash
                
                do {
                    let signature = try signer.sign(data: proofData, algorithm: .PSS)
                    context.sendMessage(msg: TLSCertificateVerify(algorithm: .rsa_pss_sha256, signature: signature))
                } catch {
                    LogError("\(error)")
                }
            }
        }
        
        func sendFinished() {
            let verifyData = finishedData(forClient: false)
            context.sendMessage(msg: TLSFinished(verifyData))
                        
            handshakeState.deriveApplicationTrafficSecrets(transcriptHash: context.transcriptHash)
            changeWriteKey(with: handshakeState.serverTrafficSecret!)
            //sema.signal()
        }
        
        func finishedData(forClient isClient: Bool) -> [UInt8] {
            let secret = isClient ? handshakeState.clientHandshakeTrafficSecret! : handshakeState.serverHandshakeTrafficSecret!

            let finishedKey = handshakeState.deriveFinishedKey(secret: secret)
            
            let transcriptHash = context.transcriptHash
            
            let finishedData = s.hashAlgorithm.hmac(finishedKey, transcriptHash)
            
            return finishedData
        }
        
        var encryptor: Encryptor!
        var decryptor: Decryptor!
                
        /*
         数据结构
         struct {
                   opaque content[TLSPlaintext.length];
                   ContentType type;
                   uint8 zeros[length_of_padding];
               } TLSInnerPlaintext;

        struct {
                   ContentType opaque_type = application_data; /* 23 */
                   ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
                   uint16 length;
                   opaque encrypted_record[TLSCiphertext.length];
               } TLSCiphertext;
         
         */
        
        func encrypt(_ data: [UInt8], contentType: ContentType, iv: [UInt8]? = nil) -> [UInt8]? {
            return encryptor.encrypt(data, contentType: contentType, iv: iv)
        }
        
        func decrypt(_ encryptedData: [UInt8], contentType: ContentType) throws -> [UInt8] {
            return try decryptor.decrypt(encryptedData, contentType: contentType)
        }
        
        func keyExchange(algorithm: KeyExchangeAlgorithm, preMasterSecret: [UInt8]) {
            
        }
                
        func changeReadKey(with trafficSecret: [UInt8]) {
            decryptor = .init(p: handshakeState.neweEncryptionParameters(withTrafficSecret: trafficSecret, cipherSuite: context.cipherSuite))            
            LogInfo("readkey changed: \(decryptor.description)")
        }
        
        func changeWriteKey(with trafficSecret: [UInt8]) {
            encryptor = .init(p: handshakeState.neweEncryptionParameters(withTrafficSecret: trafficSecret, cipherSuite: context.cipherSuite))
        }
        
        func setPendingSecurityParametersForCipherSuite(_ cipherSuite: CipherSuite) {
            do {
                context.cipherSuite = cipherSuite
                try context.keyExchange = .ecdha(.init(nil, group: selectedCurve))
            } catch {
                LogError("\(error)")
            }
        }
        
        var description: String {
            return """
                CLIENT_HANDSHAKE_TRAFFIC_SECRET \(s.clientRandom.toHexString()) \(handshakeState.clientHandshakeTrafficSecret!.toHexString())
                SERVER_HANDSHAKE_TRAFFIC_SECRET \(s.clientRandom.toHexString()) \(handshakeState.serverHandshakeTrafficSecret!.toHexString())
                CLIENT_TRAFFIC_SECRET_0 \(s.clientRandom.toHexString()) \(handshakeState.clientTrafficSecret!.toHexString())
                SERVER_TRAFFIC_SECRET_0 \(s.clientRandom.toHexString()) \(handshakeState.serverTrafficSecret!.toHexString())
                """
        }
        
        var debugDescription: String {
            switch context.keyExchange {
            case .rsa:
                return "Unsupport"
            case .ecdha(let ecdhEn):
                return """
                
                let priKey = "\(ecdhEn.privateKeyData.toHexString())".uint8Array
                let serverPubKey = "\(ecdhEn.exportPublickKey().toHexString())".uint8Array
                let clientPubKey = "\(s.preMasterSecret.toHexString())".uint8Array
                let clientRandom = "\(s.clientRandom.toHexString())".uint8Array
                let serverRandom = "\(s.serverRandom.toHexString())".uint8Array
                let transcriptHash = "\(handshakeState.handshakeTranscriptionHash.toHexString())"
                let clientHandshakeTrafficSecret = "\(handshakeState.clientHandshakeTrafficSecret!.toHexString())".uint8Array
                let serverHandshakeTrafficSecret = "\(handshakeState.serverHandshakeTrafficSecret!.toHexString())".uint8Array
                let clientTrafficSecret = "\(handshakeState.clientTrafficSecret!.toHexString())".uint8Array
                let serverTrafficSecret = "\(handshakeState.serverTrafficSecret!.toHexString())".uint8Array
                """
            }
        }
    }
    
    struct EncryptionParameters {
        var cipherSuiteDecriptor: CipherSuiteDescriptor
        var key: [UInt8]
        var iv: [UInt8]
        var sequenceNumber: UInt64 = 0
        
        var blockSize: Int {
            return cipherSuiteDecriptor.bulkCipherAlgorithm.blockSize
        }
        
        var currentIV: [UInt8] {
            // XOR the IV with the sequence number as of RFC 8446 section 5.3 Per-Record Nonce
            let sequenceNumberSize = MemoryLayout<UInt64>.size
            let ivLeftPart  = [UInt8](self.iv[0 ..< self.iv.count - sequenceNumberSize])
            let ivRightPart = [UInt8](self.iv[self.iv.count - sequenceNumberSize ..< self.iv.count])
            let iv : [UInt8] = ivLeftPart + (ivRightPart ^ sequenceNumber.bigEndianBytes)
            
            return iv
        }
    }
    
    struct Encryptor {
        var p: EncryptionParameters
        
        mutating func encrypt(_ data: [UInt8], contentType: ContentType, iv: [UInt8]? = nil) -> [UInt8]? {
            do {
                let plainText = data + [contentType.rawValue] + [UInt8](repeating: 0, count: 12)
                var authData: [UInt8] = []
                authData.append(ContentType.applicationData.rawValue)
                authData.append(contentsOf: TLSVersion.V1_2.rawValue.bytes)
                authData.append(contentsOf: UInt16(plainText.count + p.cipherSuiteDecriptor.authTagSize).bytes)
                //启用 CryptoKit
                if p.cipherSuiteDecriptor.bulkCipherAlgorithm == .chacha20 {
                    let box = try ChaChaPoly.seal(plainText, using: .init(data: p.key), nonce: .init(data: p.currentIV), authenticating: authData)
                    return (box.ciphertext + box.tag).bytes
                } else {
                    let box = try AES.GCM.seal(plainText, using: SymmetricKey(data: p.key), nonce: .init(data: p.currentIV), authenticating: authData)
                    p.sequenceNumber += 1
                    return box.ciphertext.bytes + box.tag.bytes
                }
            } catch {
                LogError("\(error)")
            }
            return nil
        }
    }
    
    struct Decryptor: CustomStringConvertible {
        var p: EncryptionParameters
        
        mutating func decrypt(_ encryptedData: [UInt8], contentType: ContentType) throws -> [UInt8] {
            //启用 CryptoKit
            if p.cipherSuiteDecriptor.bulkCipherAlgorithm == .chacha20 {
                let decrypted = try ChaChaPoly.open(.init(combined: p.currentIV+encryptedData), using: SymmetricKey(data: p.key), authenticating: []).bytes
                p.sequenceNumber += 1
                return decrypted
            } else {
                var authData: [UInt8] = []
                authData.append(ContentType.applicationData.rawValue)
                authData.append(contentsOf: TLSVersion.V1_2.rawValue.bytes)
                authData.append(contentsOf: UInt16(encryptedData.count).bytes)
            
                let message = try AES.GCM.open(.init(combined: p.currentIV + encryptedData), using: SymmetricKey(data: p.key), authenticating: authData).bytes
                p.sequenceNumber += 1
                return message
            }
        }
        
        var description: String {
            return "[sequence: \(p.sequenceNumber)] Key: \(p.key.toHexString() ) IV: \(p.iv.toHexString() )"
        }
    }
}
