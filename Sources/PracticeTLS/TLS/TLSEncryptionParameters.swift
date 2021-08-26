//
//  TLSEncryptParameters.swift
//  
//
//  Created by Rake Yang on 2021/8/16.
//

import Foundation
import CryptoSwift

public class TLSSecurityParameters
{
    public var version: TLSVersion
    public var bulkCipherAlgorithm : CipherAlgorithm
    public var blockCipherMode : BlockCipherMode
    public var cipherType : CipherType
    public var encodeKeyLength : Int = 0
    public var blockLength : Int = 0
    public var fixedIVLength : Int = 0
    public var recordIVLength : Int = 0
    public var hashAlgorithm: HashAlgorithm = .sha256
    public var hmac: MACAlgorithm
    public var preMasterSecret: [UInt8] = []
    public var masterSecret : [UInt8] = []
    public var clientRandom : [UInt8] = []
    public var serverRandom : [UInt8] = []
    public var read: TLSEncryptionParameters?
    public var write: TLSEncryptionParameters?
    
    // secure renegotiation support (RFC 5746)
    public var isUsingSecureRenegotiation: Bool = false
    public var clientVerifyData: [UInt8] = []
    public var serverVerifyData: [UInt8] = []
    
    public var isVerifyed: Bool {
        return clientVerifyData == serverVerifyData && clientVerifyData.count > 0
    }
    
    public var description: String {
        return """
            let preMasterSecret:[UInt8] = [\(preMasterSecret.toHexArray())]
            let clientRandom:[UInt8] = [\(clientRandom.toHexArray())]
            let serverRandom:[UInt8] = [\(serverRandom.toHexArray())]
            let readBulkKey:[UInt8] = [\(read!.bulkKey.toHexArray())]
            let readMacKey:[UInt8] = [\(read!.MACKey.toHexArray())]
            let writeBulkKey:[UInt8] = [\(write!.bulkKey.toHexArray())]
            let writeMacKey:[UInt8] = [\(write!.MACKey.toHexArray())]
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
        hmac                = cipherSuiteDescriptor.hashAlgorithm.macAlgorithm
    }
    
    func transformParamters() {
        masterSecret = masterSecret(preMasterSecret, seed: clientRandom+serverRandom)
        let hmacSize = cipherType == .aead ? 0 : hmac.size
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
        
        read  = TLSEncryptionParameters(MACKey: clientWriteMACKey,
                                        bulkKey: clientWriteKey,
                                        fixedIV: clientWriteIV)
        
        write = TLSEncryptionParameters(MACKey: serverWriteMACKey,
                                       bulkKey: serverWriteKey,
                                       fixedIV: serverWriteIV)
    }
    
    private func masterSecret(_ preMasterKey: [UInt8], seed: [UInt8]) -> [UInt8] {
        return P_hash(hashAlgorithm.macAlgorithm.hmacFunction, secret: preMasterKey, seed: [UInt8]("master secret".utf8)+seed, outputLength: 48)
    }
    
    public func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8] {
        return P_hash(hashAlgorithm.macAlgorithm.hmacFunction, secret: secret, seed: label + seed, outputLength: outputLength)
    }
    
    public func calculateMessageMAC(secret: [UInt8], contentType : TLSMessageType, data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        guard let MACHeader = MACHeader(contentType, dataLength: data.count, isRead: isRead) else { return nil }
        return calculateMAC(secret: secret, data: MACHeader + data, isRead: isRead)
    }
    
    public func MACHeader(_ contentType: TLSMessageType, dataLength: Int, isRead: Bool) -> [UInt8]? {
        guard let encryptionParameters = isRead ? read: write else { return nil }
        var macData: [UInt8] = []
        macData.append(contentsOf: encryptionParameters.sequenceNumber.bytes)
        macData.append(contentType.rawValue)
        macData.append(contentsOf: version.rawValue.bytes)
        macData.append(contentsOf: UInt16(dataLength).bytes)
        return macData
    }
    
    public func calculateMAC(secret : [UInt8], data : [UInt8], isRead : Bool) -> [UInt8]? {
        return hmac.hmacFunction(secret, data)
    }
}

extension TLSSecurityParameters {
    public func encrypt(_ data: [UInt8], contentType: TLSMessageType = .handeshake, iv: [UInt8]? = nil) -> [UInt8]? {
        guard let write = write else { return [] }
        let MAC = calculateMessageMAC(secret: write.MACKey, contentType: contentType, data: data, isRead: false)!
        var myPlantText = data + MAC
        if blockLength > 0 {
            let paddingLength = blockLength - ((myPlantText.count) % blockLength)
            if paddingLength != 0 {
                let padding = [UInt8](repeating: UInt8(paddingLength - 1), count: paddingLength)
                myPlantText.append(contentsOf: padding)
            }
        }
        let IV = iv ?? AES.randomIV(recordIVLength)
        do {
            let aes = try AES(key: write.bulkKey, blockMode: CBC(iv: IV), padding: .noPadding)
            return try IV+aes.encrypt(myPlantText)
        } catch {
            LogError("AES加密：\(error)")
        }
        return nil
    }
    
    public func decrypt(_ encryptedData: [UInt8], contentType: TLSMessageType = .handeshake) -> [UInt8]? {
        guard let read = read else { return nil }
        let IV = [UInt8](encryptedData[0..<recordIVLength])
        let cipherText = [UInt8](encryptedData[recordIVLength...])
        
        do {
            let aes = try AES(key: read.bulkKey, blockMode: CBC(iv: IV), padding: .noPadding)
            let message = try aes.decrypt(cipherText)
            let hmacLength = hmac.size
            var messageLength = message.count - hmacLength
            if blockLength > 0 {
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
            
            let messageMAC = calculateMessageMAC(secret: read.MACKey, contentType: contentType, data: messageContent, isRead: true)
            if let messageMAC = messageMAC, MAC == messageMAC {
                return messageContent
            } else {
                LogError("Error: MAC doesn't match")
            }
        } catch {
            LogError("AES解密：\(error)")
        }
        return nil
    }
}

public class TLSEncryptionParameters {
    public var MACKey  : [UInt8]
    public var bulkKey : [UInt8]
    public var fixedIV      : [UInt8]
    public var sequenceNumber : UInt64
    
    init(MACKey: [UInt8],
         bulkKey: [UInt8],
         fixedIV: [UInt8],
         sequenceNumber: UInt64 = UInt64(0))
    {
        self.MACKey = MACKey
        self.bulkKey = bulkKey
        self.fixedIV = fixedIV
        self.sequenceNumber = sequenceNumber
    }
}
