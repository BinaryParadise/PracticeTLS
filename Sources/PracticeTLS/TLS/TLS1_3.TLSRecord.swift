//
//  TLSRecord1_3.swift
//  
//
//  Created by Rake Yang on 2021/9/13.
//

import Foundation
import CryptoKit
import CryptoSwift

extension TLS1_3 {
    static let ivLabel  = [UInt8]("iv".utf8)
    static let keyLabel = [UInt8]("key".utf8)
    
    class TLSRecord: TLSRecordProtocol {
        var context: TLSConnection
        var handshaked: Bool = false
        var clientCipherChanged: Bool = false
        var serverCipherChanged: Bool = false
        var handshakeState: HandshakeState
        var s: TLSSecurityParameters!
        
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
                let shareSecret = try? encryptor.keyExchange(context.preMasterKey)
                s.masterSecret = shareSecret!
                handshakeState.deriveHandshakeSecret(with: shareSecret!, transcriptHash: transcriptHash ?? context.transcriptHash)
                changeKeys(with: handshakeState.clientHandshakeTrafficSecret!, isRead: true)
                changeKeys(with: handshakeState.serverHandshakeTrafficSecret!, isRead: false)
                break
            }
        }
        
        func didReadMessage(_ msg: TLSMessage, rawData: [UInt8]) throws {
            LogDebug("\(msg.type) -> \(rawData.count)")
            switch msg.type {
            case .changeCipherSpec:
                clientCipherChanged = true
            case .handshake(let handshakeType):
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                } else {
                    if msg is TLSHandshakeMessage {
                        switch handshakeType {
                        case .finished:
                            handshaked = true
                            TLSSessionManager.shared.delegate?.didHandshakeFinished(context)
                        default:break
                        }
                    }
                }
            case .alert:
                var alert: TLSAlert?
                if clientCipherChanged {
                    if let d = try decrypt([UInt8](rawData[5...]), contentType: .alert) {
                        alert = TLSAlert(stream: ([UInt8](rawData[0...4]) + d).stream, context: context)
                    }
                } else {
                    alert = TLSAlert(stream: rawData.stream, context: context)
                }
                if let alert = alert {
                    if alert.alertType == .closeNotify {
                        context.sock.disconnectAfterReadingAndWriting()
                    }
                    LogError("alert: \(alert.level) -> \(alert.alertType)")
                } else {
                    LogError("alert未识别 -> \(rawData.count)")
                }
            case .applicationData:
                let appData = msg as! TLSApplicationData
                if let decryptedData = try decrypt(appData.encryptedData, contentType: msg.type) {
                    if handshaked {
                        TLSSessionManager.shared.delegate?.didReadApplication(decryptedData, connection: context, tag: context.readWriteTag)
                    } else {
                        if let newMsg = TLSMessage.fromData(data: decryptedData, context: context) {
                            try didReadMessage(newMsg, rawData: decryptedData)
                        }
                    }
                }
            }
        }
        
        func didWriteMessage(_ tag: RWTags) -> RWTags? {
            switch tag {
            case .changeCipherSpec:
                serverCipherChanged = true
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                }
            case .handshake(let handshakeType):
                if handshakeType == .serverHello {
                    derivedSecret(context.transcriptHash)
                    let spec = TLSChangeCipherSpec()
                    spec.nextMessage = TLSEncryptedExtensions(context: context)
                    context.nextMessage = spec
                }
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                } else {
                    switch handshakeType {
                    case .helloRetryRequest:
                        return .handshake(.clientHello)
                    case .finished:
                        return .changeCipherSpec
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
            
            mutating func encrypt(_ data: [UInt8], contentType: TLSMessageType, iv: [UInt8]? = nil) -> [UInt8]? {
                do {
                    let plainText = data + [contentType.rawValue] + [UInt8](repeating: 0, count: 12)
                    var authData: [UInt8] = []
                    authData.append(TLSMessageType.applicationData.rawValue)
                    authData.append(contentsOf: TLSVersion.V1_2.rawValue.bytes)
                    authData.append(contentsOf: UInt16(plainText.count + p.cipherSuiteDecriptor.authTagSize).bytes)
                    //启用 CryptoKit
                    if p.cipherSuiteDecriptor.bulkCipherAlgorithm == .chacha20 {
                        let box = try ChaChaPoly.seal(plainText, using: .init(data: p.key), nonce: .init(data: p.currentIV), authenticating: authData)
                        return (box.ciphertext + box.tag).bytes
                    } else {
                        let box = try CryptoKit.AES.GCM.seal(plainText, using: SymmetricKey(data: p.key), nonce: .init(data: p.currentIV), authenticating: authData)
                        p.sequenceNumber += 1
                        return box.ciphertext.bytes + box.tag.bytes
                    }
                } catch {
                    LogError("\(error)")
                }
                return nil
            }
        }
        
        struct Decryptor {
            var p: EncryptionParameters
            
            mutating func decrypt(_ encryptedData: [UInt8], contentType: TLSMessageType) throws -> [UInt8]? {
                do {
                    
                    //启用 CryptoKit
                    if p.cipherSuiteDecriptor.bulkCipherAlgorithm == .chacha20 {
                        let decrypted = try ChaChaPoly.open(.init(combined: p.currentIV+encryptedData), using: SymmetricKey(data: p.key), authenticating: []).bytes
                        p.sequenceNumber += 1
                        return decrypted
                    } else {
                        let cipherData = Array(encryptedData[0..<encryptedData.count - p.cipherSuiteDecriptor.authTagSize])
                        let authTag = Array(encryptedData[(encryptedData.count - p.cipherSuiteDecriptor.authTagSize)...])
                        
                        var authData: [UInt8] = []
                        authData.append(TLSMessageType.applicationData.rawValue)
                        authData.append(contentsOf: TLSVersion.V1_2.rawValue.bytes)
                        authData.append(contentsOf: UInt16(encryptedData.count).bytes)
                    
                        let message = try CryptoKit.AES.GCM.open(.init(combined: p.currentIV + encryptedData), using: SymmetricKey(data: p.key), authenticating: authData).bytes
                        p.sequenceNumber += 1
                        return message
                    }
                } catch {
                    print("let cipherData: [UInt8] = \"\(encryptedData.toHexString())\".uint8Array")
                    print("\(error)")
                }
                return nil
            }
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
        
        func encrypt(_ data: [UInt8], contentType: TLSMessageType, iv: [UInt8]? = nil) -> [UInt8]? {
            return encryptor.encrypt(data, contentType: contentType, iv: iv)
        }
        
        func decrypt(_ encryptedData: [UInt8], contentType: TLSMessageType) throws -> [UInt8]? {
            return try decryptor.decrypt(encryptedData, contentType: contentType)
        }
        
        func keyExchange(algorithm: KeyExchangeAlgorithm, preMasterSecret: [UInt8]) {
            
        }
        
        private func changeKeys(with trafficSecret: [UInt8], isRead: Bool) {
            guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptionDictionary[context.cipherSuite]
                else {
                fatalError("Unsupported cipher suite \(context.cipherSuite)")
            }
            
            let ivSize = cipherSuiteDescriptor.fixedIVLength
            let keySize = cipherSuiteDescriptor.bulkCipherAlgorithm.keySize
            
            // calculate traffic keys and IVs as of RFC 8446 Section 7.3 Traffic Key Calculation
            let key = handshakeState.HKDF_Expand_Label(secret: trafficSecret, label: keyLabel,  hashValue: [], outputLength: keySize)
            let iv  = handshakeState.HKDF_Expand_Label(secret: trafficSecret, label: ivLabel, hashValue: [], outputLength: ivSize)
            
            if isRead {
                decryptor = .init(p: EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor, key: key, iv: iv))
            } else {
                encryptor = .init(p: EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor, key: key, iv: iv))
            }
        }
        
        func setPendingSecurityParametersForCipherSuite(_ cipherSuite: CipherSuite) {
            do {
                context.cipherSuite = cipherSuite
                try context.keyExchange = .ecdha(.init(nil, group: selectedCurve))
            } catch {
                LogError("\(error)")
            }
        }
    }
}
