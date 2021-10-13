//
//  RSAEncryptor.swift
//  GIS2020
//
//  Created by boco on 2020/9/23.
//  Copyright © 2020 gemaojing. All rights reserved.
//

import Foundation
import Security
 
/// GMJ---RSA并.p12加密解密
public class RSAEncryptor {
    
    enum RSAError: Error {
         case chunkEncryptFailed(index: Int)
         case keyCopyFailed(status: OSStatus)
         case tagEncodingFailed
         case keyCreateFailed(error: CFError?)
        case chunkDecryptFailed(index: Int)
        var localizedDescription: String {
            switch self {
            case .chunkEncryptFailed(let index):
                return "Couldn't encrypt chunk at index \(index)"
            case .keyCopyFailed(let status):
                return "Couldn't copy and retrieve key reference from the keychain: OSStatus \(status)"
            case .tagEncodingFailed:
                return "Couldn't create tag data for key"
            case .keyCreateFailed(let error):
                return "Couldn't create key reference from key data: CFError \(String(describing: error))"
            case .chunkDecryptFailed(let index):
                return "Couldn't decrypt chunk at index \(index)"
            default:
                return "Couldn't encrypt chunk at index"
            }
        }
    }
    
    var publicPEM: String!
    var privatePEM: String!
    public static let shared = RSAEncryptor()
    
    private init() {
        
    }
    
    public func setup(publicPEM: String, privatePEM: String) {
        self.publicPEM = publicPEM
        self.privatePEM = privatePEM
    }
    
    func getPrivateSecKey() -> SecKey? {
        let keyBase64 = Data(base64Encoded: self.privatePEM.rsaCleanKey)!
        let sec = SecKeyCreateWithData(keyBase64 as CFData, [kSecAttrType: kSecAttrKeyTypeRSA,
                                                             kSecMatchBits: keyBase64.count * 8 ,
                                                             kSecReturnPersistentRef: true,
                                                             kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, nil)
        return sec
    }

    func getPublicSecKey() -> SecKey? {
        let keyBase64 = Data(base64Encoded: self.publicPEM.rsaCleanKey)!
        let sec = SecKeyCreateWithData(keyBase64 as CFData, [kSecAttrType: kSecAttrKeyTypeRSA,
                                                   kSecMatchBits: keyBase64.count * 8 ,
                                                   kSecReturnPersistentRef: true,
                                                   kSecAttrKeyClass: kSecAttrKeyClassPublic] as NSDictionary, nil)
        return sec
    }
    
    // 使用'.12'私钥文件解密 11
    public func encryptData(data:Data) throws -> Data {
        let keyRef = getPublicSecKey()!
        let padding = SecPadding.PKCS1
        let blockSize = SecKeyGetBlockSize(keyRef)
              
              var maxChunkSize: Int
              switch padding {
              case []:
                  maxChunkSize = blockSize
              case .OAEP:
                  maxChunkSize = blockSize - 42
              default:
                  maxChunkSize = blockSize //- 11
              }
              
              var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
              (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
              
              var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
              var idx = 0
              
              while idx < decryptedDataAsArray.count {
                  
                  let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
                  let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
                  
                var error: Unmanaged<CFError>?
                if var encryptedDataBuffer = SecKeyCreateEncryptedData(keyRef, .rsaEncryptionPKCS1, Data(chunkData) as! CFData, &error) {
                    encryptedDataBytes.append(contentsOf: [UInt8](encryptedDataBuffer as Data))
                }
                                    
                  
                  idx += maxChunkSize
              }
              
              let encryptedData = Data(bytes: encryptedDataBytes, count: encryptedDataBytes.count)
              return encryptedData
        
    }
    
    /// 使用私钥字符串解密 13
    public func decryptData(data: [UInt8]) throws -> [UInt8] {
        let keyRef = getPrivateSecKey()!
        return self.decryptData(data: data, keyRef: keyRef)// 16
    }
    
    
    
    /// 16 私钥方法
    func decryptData(data: [UInt8], keyRef:SecKey) -> [UInt8] {
        let blockSize = SecKeyGetBlockSize(keyRef)
        
        var encryptedDataAsArray = data
        
        var decryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < encryptedDataAsArray.count {
            
            let idxEnd = min(idx + blockSize, encryptedDataAsArray.count)
            let chunkData = [UInt8](encryptedDataAsArray[idx..<idxEnd])
            
            var error:Unmanaged<CFError>? = nil
            if var decryptedDataBuffer =  SecKeyCreateDecryptedData(keyRef, .rsaEncryptionPKCS1, Data(chunkData) as CFData, &error) {
                decryptedDataBytes.append(contentsOf: [UInt8](decryptedDataBuffer as Data))
            } else {
                print("\(error ?? .none)")
            }
            
            idx += blockSize
        }
        
        return decryptedDataBytes
    }
    
    public func sign(data: [UInt8], algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) throws -> [UInt8] {
        let secKey = getPrivateSecKey()!
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(secKey, algorithm, Data(data) as CFData, &error) as? Data
        return [UInt8](signature ?? Data())
    }
    
    public func verify(signed: [UInt8], signature: [UInt8], algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256) throws -> Bool {
        //半天验证不过原来是公钥错误⚠️⚠️⚠️
        let pubSecKey = getPublicSecKey()!
        var error: Unmanaged<CFError>?
        let ret = SecKeyVerifySignature(pubSecKey, algorithm, Data(signed) as CFData, Data(signature) as CFData, &error)
        if !ret {
            print("\(error?.takeRetainedValue())")
        }
        return ret
    }
}
