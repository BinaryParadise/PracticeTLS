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
    var shared1: [UInt8] = []
    
    public init() {
        var error: Unmanaged<CFError>?
        privateKey1 = SecKeyCreateRandomKey(attributes as CFDictionary, &error)!
        if let e = error?.takeRetainedValue() {
            LogError("\(e)")
        }
        publicKey1 = SecKeyCopyPublicKey(privateKey1)!
    }
    
    func exportPublickKey() -> [UInt8] {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey1, &error) as Data? else {
            LogError("\(error!.takeRetainedValue() as Error)")
            return []
        }
        return data.bytes
    }
    
    public func exchange(_ pubKey: [UInt8]) {
        var error: Unmanaged<CFError>?
        let pubAttrs = [
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeyType: kSecAttrKeyTypeEC] as CFDictionary
        guard let pubKey2 = SecKeyCreateWithData(Data(pubKey) as NSData, pubAttrs, &error) else {
            LogError("\(error!.takeRetainedValue() as Error)")
            return
        }
        
        publicKey2 = pubKey2
        
        LogWarn("\(pubKey2)")
        
        guard let shared1 = SecKeyCopyKeyExchangeResult(privateKey1, .ecdhKeyExchangeStandardX963SHA256, pubKey2, attributes, &error) as Data? else {
            LogError("\(error!.takeRetainedValue() as Error)")
            return
        }
        self.shared1 = shared1.bytes
    }
 
    /*func generateKeyBak() {
        let attributes = [
            kSecAttrKeySizeInBits: 256,
            SecKeyKeyExchangeParameter.requestedSize.rawValue: 32,
            kSecAttrKeyType: kSecAttrKeyTypeEC,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]] as CFDictionary
        var error: Unmanaged<CFError>?
           
        privateKey1 = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
        privateKey2 = SecKeyCreateRandomKey(attributes, &error)
        
        publicKey1 = SecKeyCopyPublicKey(privateKey1!)
        publicKey2 = SecKeyCopyPublicKey(privateKey2!)
        
        guard let shared1 = SecKeyCopyKeyExchangeResult(privateKey1!, .ecdhKeyExchangeStandardX963SHA256, publicKey2!, attributes, &error) as Data? else {
            LogError("\(error!.takeRetainedValue() as Error)")
            return
        }
        self.shared1 = shared1.bytes
        guard let shared2 = SecKeyCopyKeyExchangeResult(privateKey2!, .ecdhKeyExchangeStandardX963SHA256, publicKey1!, attributes, &error) as Data? else {
            LogError("\(error!.takeRetainedValue() as Error)")
            return
        }
        self.shared2 = shared2.bytes
    }*/
    
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
