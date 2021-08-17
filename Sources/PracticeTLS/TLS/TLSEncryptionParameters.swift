//
//  TLSEncryptParameters.swift
//  
//
//  Created by Rake Yang on 2021/8/16.
//

import Foundation

class TLSSecurityParameters
{
    var bulkCipherAlgorithm : CipherAlgorithm? = nil
    var blockCipherMode : BlockCipherMode? = nil
    var cipherType : CipherType = .block
    var encodeKeyLength : Int = 0
    var blockLength : Int = 0
    var fixedIVLength : Int = 0
    var recordIVLength : Int = 0
    var hmac: MACAlgorithm? = nil
    var masterSecret : [UInt8]? = nil
    var clientRandom : [UInt8]? = nil
    var serverRandom : [UInt8]? = nil
    
    // secure renegotiation support (RFC 5746)
    var isUsingSecureRenegotiation: Bool = false
    var clientVerifyData: [UInt8] = []
    var serverVerifyData: [UInt8] = []
}

class TLSEncryptionParameters {
    var hmac : MACAlgorithm
    var bulkCipherAlgorithm : CipherAlgorithm
    var cipherType : CipherType
    var blockCipherMode : BlockCipherMode
    var MACKey  : [UInt8]
    var bulkKey : [UInt8]
    var blockLength : Int
    var fixedIVLength : Int
    var recordIVLength : Int
    var fixedIV      : [UInt8]
    var sequenceNumber : UInt64
    
    init(hmac: MACAlgorithm,
         MACKey: [UInt8],
         bulkCipherAlgorithm: CipherAlgorithm,
         blockCipherMode: BlockCipherMode = .cbc,
         bulkKey: [UInt8],
         blockLength: Int,
         fixedIVLength: Int,
         recordIVLength: Int,
         fixedIV: [UInt8],
         sequenceNumber: UInt64 = UInt64(0))
    {
        self.hmac = hmac
        self.bulkCipherAlgorithm = bulkCipherAlgorithm
        self.blockCipherMode = blockCipherMode
        
        switch blockCipherMode {
        case .cbc:
            self.cipherType = .block
        case .gcm:
            self.cipherType = .aead
        }
        
        self.MACKey = MACKey
        self.bulkKey = bulkKey
        self.blockLength = blockLength
        self.fixedIVLength = fixedIVLength
        self.recordIVLength = recordIVLength
        self.fixedIV = fixedIV
        self.sequenceNumber = sequenceNumber
    }
}
