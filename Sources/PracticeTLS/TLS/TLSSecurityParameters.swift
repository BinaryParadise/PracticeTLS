//
//  TLSEncryptParameters.swift
//  
//
//  Created by Rake Yang on 2021/8/16.
//

import Foundation
import CryptoSwift
import Crypto

class TLSSecurityParameters {
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
    public var clientVerifyData: [UInt8] = []
    public var serverVerifyData: [UInt8] = []
    
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
    }
    
    public func PRF(secret : [UInt8], label : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8] {
        return P_hash(hashAlgorithm.macAlgorithm.hmacFunction, secret: secret, seed: label + seed, outputLength: outputLength)
    }
}
