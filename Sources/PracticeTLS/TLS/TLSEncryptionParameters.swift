//
//  TLSEncryptParameters.swift
//  
//
//  Created by Rake Yang on 2021/8/16.
//

import Foundation

public class TLSSecurityParameters
{
    public var version: TLSVersion = .V1_2
    public var bulkCipherAlgorithm : CipherAlgorithm = .aes256
    public var blockCipherMode : BlockCipherMode = .cbc
    public var cipherType : CipherType = .block
    public var encodeKeyLength : Int = 0
    public var blockLength : Int = 0
    public var fixedIVLength : Int = 0
    public var recordIVLength : Int = 0
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
    
    init() {
        guard let cipherSuiteDescriptor = TLSCipherSuiteDescriptionDictionary[.TLS_RSA_WITH_AES_256_CBC_SHA256]
            else {
                fatalError("Unsupported cipher suite")
        }
        let cipherAlgorithm = cipherSuiteDescriptor.bulkCipherAlgorithm
        
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
        return PRF(secret: preMasterKey, label: [UInt8]("master secret".utf8), seed: seed, outputLength: 48)
    }
    
    public func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8] {
        return P_hash(hmac.hmacFunction, secret: secret, seed: label + seed, outputLength: outputLength)
    }
    
    public func calculateMessageMAC(secret: [UInt8], contentType : TLSMessageType, data : [UInt8], isRead : Bool) -> [UInt8]?
    {
        guard let MACHeader = MACHeader(contentType, dataLength: data.count, isRead: isRead) else { return nil }
        return calculateMAC(secret: secret, data: MACHeader + data, isRead: isRead)
    }
    
    public func MACHeader(_ contentType: TLSMessageType, dataLength: Int, isRead: Bool) -> [UInt8]? {
        guard let encryptionParameters = isRead ? read: write else { return nil }
        var macData: [UInt8] = []
        macData.append(contentsOf: encryptionParameters.sequenceNumber.bytes())
        macData.append(contentType.rawValue)
        macData.append(contentsOf: TLSVersion.V1_2.rawValue.bytes())
        macData.append(contentsOf: UInt16(dataLength).bytes())
        return macData
    }
    
    public func calculateMAC(secret : [UInt8], data : [UInt8], isRead : Bool) -> [UInt8]? {
        return hmac.hmacFunction(secret, data)
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
