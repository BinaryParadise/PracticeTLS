//
//  TLSCipherDescriptions.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 12.04.15.
//  Copyright (c) 2015 Nico Schmidt. All rights reserved.
//

import Foundation

public enum CipherType {
    case block
    case stream
    case aead
}

struct CipherSuiteDescriptor {
    let cipherSuite : CipherSuite
    let keyExchangeAlgorithm: KeyExchangeAlgorithm
    let bulkCipherAlgorithm : CipherAlgorithm
    let cipherType : CipherType
    let blockCipherMode : BlockCipherMode
    let fixedIVLength : Int
    let recordIVLength : Int
    let authTagSize : Int // only for AEAD
    let hashAlgorithm: HashAlgorithm
    
    public let supportedProtocolVersions: [TLSVersion]
    
    init(cipherSuite: CipherSuite,
         keyExchangeAlgorithm: KeyExchangeAlgorithm = .rsa,
         bulkCipherAlgorithm: CipherAlgorithm,
         cipherType: CipherType,
         blockCipherMode: BlockCipherMode? = nil,
         fixedIVLength: Int = 0,
         recordIVLength: Int = 0,
         authTagSize: Int = 0,
         hashFunction: HashAlgorithm,
         supportedProtocolVersions: [TLSVersion] = [.V1_2]
    )
    {
        self.cipherSuite = cipherSuite
        self.keyExchangeAlgorithm = keyExchangeAlgorithm
        self.bulkCipherAlgorithm = bulkCipherAlgorithm
        self.cipherType = cipherType
        self.blockCipherMode = blockCipherMode ?? .cbc
        self.fixedIVLength = fixedIVLength != 0 ? fixedIVLength : bulkCipherAlgorithm.blockSize
        self.recordIVLength = recordIVLength != 0 ? recordIVLength : bulkCipherAlgorithm.blockSize
        self.authTagSize = authTagSize
        
        self.hashAlgorithm = hashFunction
        self.supportedProtocolVersions = supportedProtocolVersions
    }
}


let TLSCipherSuiteDescriptions : [CipherSuiteDescriptor] = [
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_256_CBC_SHA,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),
    
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_256_CBC_SHA256,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha256
    ),
    CipherSuiteDescriptor(
        cipherSuite: .TLS_RSA_WITH_AES_128_GCM_SHA256,
        bulkCipherAlgorithm: .aes128,
        cipherType: .aead,
        blockCipherMode: .gcm,
        fixedIVLength: 4,
        recordIVLength: 8,
        authTagSize: 16,
        hashFunction: .sha256
    ),
    CipherSuiteDescriptor(
        cipherSuite: .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        keyExchangeAlgorithm: .ecdhe,
        bulkCipherAlgorithm: .aes256,
        cipherType: .block,
        blockCipherMode: .cbc,
        hashFunction: .sha1
    ),
]

let TLSCipherSuiteDescriptionDictionary : [CipherSuite:CipherSuiteDescriptor] = {
    var dict = [CipherSuite:CipherSuiteDescriptor]()
    for cipherSuite in TLSCipherSuiteDescriptions {
        dict[cipherSuite.cipherSuite] = cipherSuite
    }
    
    return dict
}()
