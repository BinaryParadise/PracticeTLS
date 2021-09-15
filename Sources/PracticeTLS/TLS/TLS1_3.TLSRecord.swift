//
//  TLSRecord1_3.swift
//  
//
//  Created by Rake Yang on 2021/9/13.
//

import Foundation
import CryptoKit

extension TLS1_3 {
    static let ivLabel  = [UInt8]("iv".utf8)
    static let keyLabel = [UInt8]("key".utf8)
    
    class TLSRecord: TLSRecordProtocol {
        var context: TLSConnection
        var handshaked: Bool = false
        var cipherChanged: Bool = false
        var handshakeState: HandshakeState
        var s: TLSSecurityParameters!
        
        required init(_ context: TLSConnection) {
            self.context = context
            handshakeState = TLS1_3.HandshakeState()
            s = TLSSecurityParameters(context.cipherSuite)
        }
        
        func derivedSecret() {
            handshakeState.deriveEarlySecret()
            
            switch context.keyExchange {
            case .rsa:
                break
            case .ecdha(let encryptor):
                let shareSecret = try? encryptor.keyExchange(context.preMasterKey)
                handshakeState.deriveHandshakeSecret(with: shareSecret!, transcriptHash: context.transcriptHash)
                changeKeys(with: handshakeState.clientHandshakeTrafficSecret!, isRead: true)
                changeKeys(with: handshakeState.serverHandshakeTrafficSecret!, isRead: false)
                break
            }
        }
        
        func didReadMessage(_ msg: TLSMessage, rawData: [UInt8]) throws {
            LogDebug("\(msg.type) -> \(rawData.count)")
            switch msg.type {
            case .changeCipherSpec:
                cipherChanged = true
            case .handshake(let handshakeType):
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                } else {
                    if let handshakeMsg = msg as? TLSHandshakeMessage {
                        context.handshakeMessages.append(handshakeMsg)
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
                if cipherChanged {
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
                cipherChanged = true
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                }
            case .handshake(let handshakeType):
                if let msg = context.nextMessage {
                    context.sendMessage(msg: msg)
                } else {
                    switch handshakeType {
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
                        
            mutating func encrypt(_ data: [UInt8], contentType: TLSMessageType, authData: [UInt8], iv: [UInt8]? = nil) -> [UInt8]? {
                do {
                    //启用 CryptoKit
                    if cipherSuiteDecriptor.bulkCipherAlgorithm == .chacha20 {
                        //TODO:
                        return nil
                    } else {
                        let box = try CryptoKit.AES.GCM.seal(data, using: SymmetricKey(data: key), nonce: .init(data: currentIV), authenticating: authData)
                        sequenceNumber += 1
                        return box.ciphertext.bytes + box.tag.bytes
                    }
                } catch {
                    LogError("\(error)")
                }
                return nil
            }
            
            mutating func decrypt(_ encryptedData: [UInt8], authData: [UInt8], contentType: TLSMessageType) throws -> [UInt8]? {
                do {
                    //启用 CryptoKit
                    if cipherSuiteDecriptor.bulkCipherAlgorithm == .chacha20 {
                        let decrypted = try ChaChaPoly.open(.init(combined: currentIV+encryptedData), using: SymmetricKey(data: key), authenticating: authData).bytes
                        sequenceNumber += 1
                        return decrypted
                    } else {
                        let message = try CryptoKit.AES.GCM.open(.init(combined: currentIV+encryptedData), using: SymmetricKey(data: key), authenticating: authData).bytes
                        sequenceNumber += 1
                        return message
                    }
                } catch {
                    print("let cipherData: [UInt8] = \"\(encryptedData.toHexString())\".uint8Array")
                    print("\(error)")
                }
                return nil
            }
        }
        
        var readEncryptionParameters: EncryptionParameters!
        var writeEncryptionParameters: EncryptionParameters!
        
        func encrypt(_ data: [UInt8], contentType: TLSMessageType, iv: [UInt8]? = nil) -> [UInt8]? {
            let paddingLength = 12
            let padding = [UInt8](repeating: 0, count: paddingLength)
            let plainTextRecordData = data + [contentType.rawValue] + padding

            var authDataBuffer: [UInt8] = []
            authDataBuffer.append(contentType.rawValue)
            authDataBuffer.append(contentsOf: TLSVersion.V1_2.rawValue.bytes)
            authDataBuffer.append(contentsOf: UInt16(plainTextRecordData.count + writeEncryptionParameters.cipherSuiteDecriptor.authTagSize).bytes)
            return writeEncryptionParameters.encrypt(plainTextRecordData, contentType: contentType, authData: authDataBuffer, iv: iv)
        }
        
        func decrypt(_ encryptedData: [UInt8], contentType: TLSMessageType) throws -> [UInt8]? {
            let cipherText = [UInt8](encryptedData[0..<(encryptedData.count - readEncryptionParameters.cipherSuiteDecriptor.authTagSize)])
            let authTag    = [UInt8](encryptedData[(encryptedData.count - readEncryptionParameters.cipherSuiteDecriptor.authTagSize)..<encryptedData.count])
            
            var authDataBuffer: [UInt8] = []
            authDataBuffer.append(contentType.rawValue)
            authDataBuffer.append(contentsOf: TLSVersion.V1_2.rawValue.bytes)
            authDataBuffer.append(contentsOf: UInt16((cipherText + authTag).count).bytes)
            return try readEncryptionParameters.decrypt(cipherText, authData: authDataBuffer, contentType: contentType)
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
                readEncryptionParameters = EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor, key: key, iv: iv)
            } else {
                writeEncryptionParameters = EncryptionParameters(cipherSuiteDecriptor: cipherSuiteDescriptor, key: key, iv: iv)
            }
        }
        
        func setPendingSecurityParametersForCipherSuite(_ cipherSuite: CipherSuite) {
            do {
                try context.keyExchange = .ecdha(.init())
            } catch {
                LogError("\(error)")
            }
        }
        
    }
}
