//
//  SwiftTLSCrypto.swift
//  SwiftTLS
//
//  Created by Nico Schmidt on 18.04.18.
//  Copyright © 2018 Nico Schmidt. All rights reserved.
//

import Foundation

extension AES : Cryptor {
    func update(inputBlock: MemoryBlock, outputBlock: inout MemoryBlock) -> Bool {
        update(indata: inputBlock.block, outdata: &outputBlock.block)
        
        return true
    }
}

public enum CipherAlgorithm
{
    case null
    case aes128
    case aes256
    
    var blockSize : Int {
        get {
            switch self {
            case .null: return 0
            case .aes128: return 16
            case .aes256: return 16
            }
            
        }
    }
    
    var keySize : Int {
        get {
            switch self {
            case .null: return 0
            case .aes128: return 16
            case .aes256: return 32
            }
        }
    }
}

public enum BlockCipherMode {
    case cbc
    case gcm
}

extension BlockCipher {
    class func encryptionBlockCipher(_ cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8]) -> BlockCipher?
    {
        let aes: AES
        switch cipherAlgorithm {
        case .aes128:
            aes = AES(key: key, bitSize: .aes128, encrypt: true)
            
        case .aes256:
            aes = AES(key: key, bitSize: .aes256, encrypt: true)

        default:
            fatalError("Unsupported cipher algorithm \(cipherAlgorithm)")
        }
        
        let cipher = BlockCipher(encrypt: true, cryptor: aes, mode: mode, cipher: cipherAlgorithm)
        
        return cipher
    }
    
    class func decryptionBlockCipher(_ cipherAlgorithm : CipherAlgorithm, mode: BlockCipherMode, key : [UInt8]) -> BlockCipher?
    {
        let aes: AES
        switch cipherAlgorithm {
        case .aes128:
            aes = AES(key: key, bitSize: .aes128, encrypt: (mode == .gcm))
            
        case .aes256:
            aes = AES(key: key, bitSize: .aes256, encrypt: (mode == .gcm))
            
        default:
            fatalError("Unsupported cipher algorithm \(cipherAlgorithm)")
        }

        let cipher = BlockCipher(encrypt: false, cryptor: aes, mode: mode, cipher: cipherAlgorithm)
        
        return cipher
    }
}

func HMAC_MD5(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    fatalError("MD5 not implemented")
}

func HMAC_SHA1(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    return HMAC(hash: SHA1.self, secret: secret, data: data)
}

func HMAC_SHA256(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    return HMAC(hash: SHA256.self, secret: secret, data: data)
}

func HMAC_SHA384(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    return HMAC(hash: SHA384.self, secret: secret, data: data)
}

func HMAC_SHA512(_ secret : [UInt8], data : [UInt8]) -> [UInt8]
{
    return HMAC(hash: SHA384.self, secret: secret, data: data)
}

func Hash_MD5(_ data : [UInt8]) -> [UInt8]
{
    fatalError("MD5 not implemented")
}

func Hash_SHA1(_ data : [UInt8]) -> [UInt8]
{
    return SHA1.hash(data)
}

func Hash_SHA224(_ data : [UInt8]) -> [UInt8]
{
    return SHA224.hash(data)
}

func Hash_SHA256(_ data : [UInt8]) -> [UInt8]
{
    return SHA256.hash(data)
}

func Hash_SHA384(_ data : [UInt8]) -> [UInt8]
{
    return SHA384.hash(data)
}

func Hash_SHA512(_ data : [UInt8]) -> [UInt8]
{
    return SHA512.hash(data)
}
