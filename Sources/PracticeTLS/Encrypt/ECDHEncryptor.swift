//
//  ECDHEncryptor.swift
//  
//
//  Created by Rake Yang on 2021/9/7.
//

import Foundation

public class ECDHEncryptor {
    let attributes = [
        kSecAttrKeySizeInBits: 256,
        SecKeyKeyExchangeParameter.requestedSize.rawValue: 32,
        kSecAttrKeyType: kSecAttrKeyTypeEC,
        kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]] as CFDictionary
    var privateKey1: SecKey
    var publicKey1: SecKey
    var publicKey2: SecKey?
    
    public init(_ priKeyData: [UInt8]? = nil) throws {
        var error: Unmanaged<CFError>?
        if let pkd = priKeyData {
            guard let _priKey1 = SecKeyCreateWithData(Data(pkd) as CFData, [
                                                        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                                                        kSecAttrKeyType: kSecAttrKeyTypeEC] as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error
            }
            privateKey1 = _priKey1
        } else {
            guard let _priKey1 = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw error!.takeRetainedValue() as Error                
            }
            privateKey1 = _priKey1
        }
        if let e = error?.takeRetainedValue() {
            LogError("\(e)")
        }
        publicKey1 = SecKeyCopyPublicKey(privateKey1)!
        
        print("\(privateKey1)")
        let x = SecKeyCopyExternalRepresentation(privateKey1, nil) as! Data
        print("\(publicKey1)")
    }
    
    func exportPublickKey() -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey1, &error) as Data? else {
            LogError("\(error!.takeRetainedValue() as Error)")
            return []
        }
        return data.bytes
    }
    
    public func keyExchange(_ pubKey: [UInt8]) throws -> [UInt8] {
        var error: Unmanaged<CFError>?
        let pubAttrs = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeEC] as CFDictionary
        guard let pubKey2 = SecKeyCreateWithData(Data(pubKey) as CFData, pubAttrs, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        guard let shared1 = SecKeyCopyKeyExchangeResult(privateKey1, .ecdhKeyExchangeStandard, pubKey2, attributes, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return Array(shared1.bytes)
    }
    
    public func encrypt(_ sourceData: [UInt8], algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA512AESGCM) -> [UInt8]? {
        var error: Unmanaged<CFError>?
        let encrypted = SecKeyCreateEncryptedData(publicKey1, algorithm,
                                      Data(sourceData) as CFData,
                                      &error)
        if error == nil {
            return (encrypted! as Data).bytes
        } else {
            LogError("\(error!.takeRetainedValue() as Error)")
        }
        return nil
    }
    
    func decrypt(_ sourceData: [UInt8], algorithm: SecKeyAlgorithm = .eciesEncryptionStandardX963SHA512AESGCM) -> [UInt8]? {
        var error: Unmanaged<CFError>?
        let resData = SecKeyCreateDecryptedData(privateKey1, algorithm,
                                                Data(sourceData) as CFData, &error)
        
        if error == nil {
            return (resData! as Data).bytes
        }
        return nil
    }
}
