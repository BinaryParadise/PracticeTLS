//
//  TLSEncryptParameters.swift
//  
//
//  Created by Rake Yang on 2021/8/16.
//

import Foundation
import CryptoSwift
import CryptoKit

public class TLSSecurityParameters: CustomStringConvertible
{
    public var version: TLSVersion
    public var bulkCipherAlgorithm : CipherAlgorithm
    public var blockCipherMode : BlockCipherMode
    public var cipherType : CipherType
    public var encodeKeyLength : Int = 0
    public var blockLength : Int = 0
    public var fixedIVLength : Int = 0
    public var recordIVLength : Int = 0
    public var authTagSize: Int = 0
    public var hashAlgorithm: HashAlgorithm = .sha256
    public var preMasterSecret: [UInt8] = []
    public var masterSecret : [UInt8] = []
    public var clientRandom : [UInt8] = []
    public var serverRandom : [UInt8] = []
    public var readEncryptionParameters: TLSEncryptionParameters
    public var writeEncryptionParameters: TLSEncryptionParameters
    
    // secure renegotiation support (RFC 5746)
    public var isUsingSecureRenegotiation: Bool = false
    public var clientVerifyData: [UInt8] = []
    public var serverVerifyData: [UInt8] = []
    
    public var isVerifyed: Bool {
        return clientVerifyData == serverVerifyData && clientVerifyData.count > 0
    }
    
    let handshakeState = TLS1_3.HandshakeState()
        
    public var description: String {
        return """
            let preMasterSecret:[UInt8] = [\(preMasterSecret.toHexArray())]
            let clientRandom:[UInt8] = [\(clientRandom.toHexArray())]
            let serverRandom:[UInt8] = [\(serverRandom.toHexArray())]
            let readBulkKey:[UInt8] = [\(readEncryptionParameters.bulkKey.toHexArray())]
            let readFixedIV:[UInt8] = \"(\(readEncryptionParameters.fixedIV.toHexString())\".uint8Array
            let readMacKey:[UInt8] = [\(readEncryptionParameters.MACKey.toHexArray())]
            
            let writeBulkKey:[UInt8] = [\(writeEncryptionParameters.bulkKey.toHexArray())]
            let writeMacKey:[UInt8] = [\(writeEncryptionParameters.MACKey.toHexArray())]
            let writeFixedIV:[UInt8] = \"(\(writeEncryptionParameters.fixedIV.toHexString())\".uint8Array
            let clientVerifyData:[UInt8] = [\(clientVerifyData.toHexArray())]
            let serverVerifyData:[UInt8] = [\(serverVerifyData.toHexArray())]
            """
    }
    
    init(_ cipherSuite: CipherSuite) {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptionDictionary[cipherSuite]
            else {
                fatalError("Unsupported cipher suite")
        }
        let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
        version             = cipherSuiteDescriptor.supportedProtocolVersions.first!
        bulkCipherAlgorithm = cipherAlgorithm
        blockCipherMode     = cipherSuiteDescriptor.blockCipherMode
        cipherType          = cipherSuiteDescriptor.cipherType
        encodeKeyLength     = cipherAlgorithm.keySize
        blockLength         = cipherAlgorithm.blockSize
        fixedIVLength       = cipherSuiteDescriptor.fixedIVLength
        recordIVLength      = cipherSuiteDescriptor.recordIVLength
        authTagSize         = cipherSuiteDescriptor.authTagSize
        readEncryptionParameters = TLSEncryptionParameters(MACKey: [], bulkKey: [], fixedIV: [], hmac: cipherSuiteDescriptor.hashAlgorithm.macAlgorithm)
        writeEncryptionParameters = TLSEncryptionParameters(MACKey: [], bulkKey: [], fixedIV: [], hmac: cipherSuiteDescriptor.hashAlgorithm.macAlgorithm)
    }
    
    func keyExchange(algorithm: KeyExchangeAlgorithm, preMasterSecret: [UInt8]) {
        masterSecret = masterSecret(preMasterSecret, seed: clientRandom+serverRandom)
        let hmacSize = cipherType == .aead ? 0 : readEncryptionParameters.hmac.size
        let numberOfKeyMaterialBytes = 2 * (hmacSize + encodeKeyLength + fixedIVLength)
        let keyBlock = PRF(secret: masterSecret, label: TLSKeyExpansionLabel, seed: serverRandom + clientRandom, outputLength: numberOfKeyMaterialBytes)
        
        var index = 0
        let clientWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
        index += hmacSize
        
        let serverWriteMACKey = [UInt8](keyBlock[index..<index + hmacSize])
        index += hmacSize
        
        let clientWriteKey = [UInt8](keyBlock[index..<index + encodeKeyLength])
        index += encodeKeyLength
        
        let serverWriteKey = [UInt8](keyBlock[index..<index + encodeKeyLength])
        index += encodeKeyLength
        
        let clientWriteIV = [UInt8](keyBlock[index..<index + fixedIVLength])
        index += fixedIVLength
        
        let serverWriteIV = [UInt8](keyBlock[index..<index + fixedIVLength])
        index += fixedIVLength
        
        let hmac = readEncryptionParameters.hmac
        
        readEncryptionParameters  = TLSEncryptionParameters(MACKey: clientWriteMACKey,
                                        bulkKey: clientWriteKey,
                                        fixedIV: clientWriteIV,
                                        hmac: hmac)
        readEncryptionParameters.title = "解密"
        
        writeEncryptionParameters = TLSEncryptionParameters(MACKey: serverWriteMACKey,
                                       bulkKey: serverWriteKey,
                                       fixedIV: serverWriteIV,
                                       hmac: hmac)
        writeEncryptionParameters.title = "加密"
    }
    
    private func masterSecret(_ preMasterKey: [UInt8], seed: [UInt8]) -> [UInt8] {
        preMasterSecret = preMasterKey
        return P_hash(hashAlgorithm.macAlgorithm.hmacFunction, secret: preMasterKey, seed: [UInt8]("master secret".utf8)+seed, outputLength: 48)
    }
    
    public func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8] {
        return P_hash(hashAlgorithm.macAlgorithm.hmacFunction, secret: secret, seed: label + seed, outputLength: outputLength)
    }
}

extension TLSSecurityParameters {
    public func encrypt(_ data: [UInt8], contentType: TLSMessageType, iv: [UInt8]? = nil) -> [UInt8]? {
        //PS: CryptoSwift的padding处理异常导致加解密有问题⚠️⚠️⚠️
        let encryption = writeEncryptionParameters
        let isAEAD = cipherType == .aead
        let MAC = isAEAD ? [] : encryption.calculateMessageMAC(secret: encryption.MACKey, contentType: contentType, data: data)!
        let myPlantText = data + MAC
        let recordIV = iv ?? AES.randomIV(recordIVLength)
        let IV = (isAEAD ? encryption.fixedIV:[]) + recordIV
        do {
            let macHeader = isAEAD ? encryption.MACHeader(contentType, dataLength: myPlantText.count) ?? [] : []
            //启用 CryptoKit
            #if true
            
            let key = SymmetricKey(data: encryption.bulkKey)
            if bulkCipherAlgorithm == .chacha20 {
                let nonce = (0.bytes + encryption.sequenceNumber.bytes) ^ encryption.fixedIV
                let sealedBox = try ChaChaPoly.seal(myPlantText, using: key, nonce: .init(data: nonce), authenticating: macHeader)
                encryption.sequenceNumber += 1
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
            
            encryption.sequenceNumber += 1
            return cipherText
        } catch {
            fatalError("AES加密：\(error)")
        }
        return nil
    }
    
    public func decrypt(_ encryptedData: [UInt8], contentType: TLSMessageType) throws -> [UInt8]? {
        let decryption = readEncryptionParameters
        if encryptedData.count < recordIVLength+blockLength {
            return nil
        }
        let isAEAD = cipherType == .aead
        let IV = (isAEAD ? decryption.fixedIV :[]) + [UInt8](encryptedData[0..<recordIVLength])
        
        let cipherText: [UInt8]
        
        var authTag : [UInt8] = []
        if blockCipherMode == .gcm {
            cipherText = [UInt8](encryptedData[recordIVLength..<(encryptedData.count - authTagSize)])
            authTag = [UInt8](encryptedData[(encryptedData.count - authTagSize)..<encryptedData.count])
        } else {
            cipherText = [UInt8](encryptedData[recordIVLength..<encryptedData.count])
        }
        
        let macHeader = isAEAD ? decryption.MACHeader(contentType, dataLength: cipherText.count) ?? [] : []
        

        do {
            //启用 CryptoKit
            #if true
            
            let key = SymmetricKey(data: decryption.bulkKey)
            if bulkCipherAlgorithm == .chacha20 {
                let nonce = (0.bytes + decryption.sequenceNumber.bytes) ^ decryption.fixedIV
                let decrypted = try ChaChaPoly.open(.init(combined: nonce+encryptedData), using: key, authenticating: macHeader).bytes
                decryption.sequenceNumber += 1
                return decrypted
            }
            
            let message = try CryptoKit.AES.GCM.open(.init(combined: IV+cipherText+authTag), using: key, authenticating: macHeader).bytes
            decryption.sequenceNumber += 1
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
            let messageLength = message.count - decryption.hmac.size
            let messageContent = [UInt8](message[0..<messageLength])
            
            let MAC = isAEAD ? [] : [UInt8](message[messageLength..<messageLength + decryption.hmac.size])
            
            let messageMAC = decryption.calculateMessageMAC(secret: decryption.MACKey, contentType: contentType, data: messageContent)
            if MAC == messageMAC {
                decryption.sequenceNumber += 1
                return messageContent
            } else {
                fatalError("Error: MAC doesn't match")
            }
        } catch {
            print("let cipherData: [UInt8] = \"\(encryptedData.toHexString())\".uint8Array")
            print(description)
            print("\(error)")
        }
        return nil
    }
}

public class TLSEncryptionParameters {
    public var MACKey  : [UInt8]
    public var bulkKey : [UInt8]
    public var fixedIV      : [UInt8]
    public var sequenceNumber : UInt64
    public var hmac: MACAlgorithm
    public var title = ""
    
    init(MACKey: [UInt8],
         bulkKey: [UInt8],
         fixedIV: [UInt8],
         sequenceNumber: UInt64 = UInt64(0), hmac: MACAlgorithm = .hmac_sha256)
    {
        self.MACKey = MACKey
        self.bulkKey = bulkKey
        self.fixedIV = fixedIV
        self.sequenceNumber = sequenceNumber
        self.hmac = hmac
    }
    
    public func calculateMessageMAC(secret: [UInt8], contentType : TLSMessageType, data : [UInt8]) -> [UInt8]?
    {
        let MACHeader = MACHeader(contentType, dataLength: data.count) ?? []
        return calculateMAC(secret: secret, data: MACHeader + data)
    }
    
    public func calculateMAC(secret : [UInt8], data : [UInt8]) -> [UInt8]? {
        return hmac.hmacFunction(secret, data)
    }
    
    func MACHeader(_ contentType: TLSMessageType, dataLength: Int, version: TLSVersion = .V1_2) -> [UInt8]? {
        //LogWarn("\(title) -> sequenceNumber: \(sequenceNumber)")
        var macData: [UInt8] = []
        macData.append(contentsOf: sequenceNumber.bytes)
        macData.append(contentType.rawValue)
        macData.append(contentsOf: version.rawValue.bytes)
        macData.append(contentsOf: UInt16(dataLength).bytes)
        return macData
    }
}
