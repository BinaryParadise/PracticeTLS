//
//  RSAEncryptor.swift
//  GIS2020
//
//  Created by boco on 2020/9/23.
//  Copyright © 2020 gemaojing. All rights reserved.
//

import Foundation
import Security

#if false
//测试
public let kRSAPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQg49cH7GmFgwYZvF7tT65CsE0nYHAaoSAPshbojdP28mkZy2IWlm50nqFlZxIPhTltJHNddX3l1StvrE83F9QYPsAfPcPTIfftOhEXKqCKErDISDNT3QDE4YkHV925LEPDK+rShZoPfE2l3qB2gpQMZ1fLoDRkHw9HQRTWRulRwIDAQAB"
public let kRSAPrivateKey = "MIICXgIBAAKBgQDQg49cH7GmFgwYZvF7tT65CsE0nYHAaoSAPshbojdP28mkZy2IWlm50nqFlZxIPhTltJHNddX3l1StvrE83F9QYPsAfPcPTIfftOhEXKqCKErDISDNT3QDE4YkHV925LEPDK+rShZoPfE2l3qB2gpQMZ1fLoDRkHw9HQRTWRulRwIDAQABAoGBAK1PLDEeBsJNQPBnX/+6vc9/qObao6YS4t7VUCMZyW+O9yK2v5m9vyY8U6oEmElTkHr8gtOLRbTtC2z+OsKjSHQ9WJtrAZB0gxugdObk8BzszVmj5huiWTnyVd38RcRtk5owmShFzc1/Iol7ir/cGAddrcdqxcT1bRsL5oMHzuIBAkEA+lg+9nBr35IFjYHhJkI1H37DTpfMV1MOkZ6AcAYj/m4mr3CR6tJuh8JPEC/zkP5iypK5yOBiPHHWwu+xlA1SpwJBANU5Z50F9tNSMMLmXy5UI9eb4dBbD+SrB6CyqcuifCDDOnT+A5uxhLknO03l2rBAbzybj0mEY3hZk9cCU7nEjGECQQDFiNwlmI+F2bKH9fOyPIuuTlfNq/mQ7fiQ7oBp5G6CVGgyBqEcqO6OMMQyAaQuxIsvTJdL6cGZ8DmFl5yHNfwBAkBy0oL1kCynB++yRRSkgjL6/LrR1PfuEBv/cbb2Lf3iNr/YGKIgyavLeVD6Vfk6SLieTrcOw/g86yAt/NbRhwKBAkEAwG2AH/5jCLneXCS01+6SzKRJEqwdiTb1VtV1YFdcJLQMWyDjSJYeQfWBu6e0EhOE35igfZ6QkmZaMVKcLmJabw=="
#else
 
public let kRSAPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwlrILgRpHj+i847BwDov
    ZxYAWwjIejcogloLjwSz3fecsHbQ5sG+Z4wotx50OefEtOIoZnh5T6/7HO9ZI0eQ
    yCNOwrDCmACAcrEoyzk/0dytFyYLPcdRgC+foSQ5Bgor3QmlwojRHxUP5KTl90ef
    tVI/GyCTtzHIewOQk6cu8W4o531gYDGuU1lrVaGiyqQsQrNZ38HoO+Iv+WKyBjJS
    C1DYoYe+w2tra3H+PWRTsNCbHDADzX36uG2lD/msqC08tl1G9yTK1Jri5MlB1+Bw
    Hcj127peKDjpq7ydrcxCtflzFueTq/wpc3D7kUrFbOZba8WMPRnjxGllqTZC3zUl
    BwIDAQAB
    -----END PUBLIC KEY-----
    """

public let kRSAPrivateKey = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAwlrILgRpHj+i847BwDovZxYAWwjIejcogloLjwSz3fecsHbQ
    5sG+Z4wotx50OefEtOIoZnh5T6/7HO9ZI0eQyCNOwrDCmACAcrEoyzk/0dytFyYL
    PcdRgC+foSQ5Bgor3QmlwojRHxUP5KTl90eftVI/GyCTtzHIewOQk6cu8W4o531g
    YDGuU1lrVaGiyqQsQrNZ38HoO+Iv+WKyBjJSC1DYoYe+w2tra3H+PWRTsNCbHDAD
    zX36uG2lD/msqC08tl1G9yTK1Jri5MlB1+BwHcj127peKDjpq7ydrcxCtflzFueT
    q/wpc3D7kUrFbOZba8WMPRnjxGllqTZC3zUlBwIDAQABAoIBAHwpmvErCCy24tdO
    QCEaCuaEe72sosbRLiP4eqHnkzEe2w8xGMwSwh1MwUYbQo0rr9MPGFg+ZuGtv3MA
    xaVwNuJlDA/89JQ+3dBntXP/IvJjVIERYOUazMpjoktD5Noi7VrMqwTYeyCsR/b+
    EZwkObeQz5f4++Vw/G76HAb4K1k4tVj+Bhqtq228ELbrcbEN9UKSCVdo/zAvw0B/
    qLvXi8j2qu5ONo0zeOy/PGsyGWGr2++/nqraAuDj6wPBzwIyz2sIA61gitjjBU5i
    xA+dHbEh+ES4KEL1c2BfavoioG+Ac2DNfPX8mTB/TE6rma97myaahKxZGrbAtZQY
    BLA8RgECgYEA72/quC9dhHgXP/gSweBXk2vnPg7OFZVh2rrEDnY+qch0qpV5hG/1
    vZPgFh/KtZ78ZAd3sb2EtS1/OfwvhGBbCbhzO+LR642kAudcAz6Zj5bNjW3EKRvG
    wvhr+fs+xAOole9hLUd8V5Tww+541hgNPTDqxfBCrFkaC/bSnTAeYccCgYEAz8yE
    y4DnsUI0XDbEXTTyVWGTROvEs4IjkWKBhs2PL9Pnh2j2vjsJ1OAa0H+74RwkgBcF
    kWrhGMRj3YR2OcSRvjHK8NojIQ9cPT0wFcObLNisWggqay3eiLEYwd5x14OrXVrI
    hewCstmU8+A1sjeKLTWDOFRWn3zylHCJ/gYnIsECgYBzru8I7lmQlzUkgwcNBQdL
    AudG5IBNjU8qDvKKyjaccW1svatogW+JmNi718Bo39exvKnoBlkH8GN38JBEtQlH
    OQbz+DLUTCrh/EZIiwZGieXmXxJXikQOD1ib/vfkXKAnUPDyn4dECYIKKD3ZsuUy
    m1/TIrIT8zjSbv5zU7xaIQKBgQCsLDv3VdYjM8SohyRKSh1kCxX3rBXt2i1YP7Ms
    m1NBgKU8uAaBde9ed1UgXkWwbh38F5cgdtsNJ2PLXf6LPMi5Ow54Y3Vp5g06HGGk
    Fs+S5/BeJJfo+DeDMKFfuMzAkbNCBX9SH0vZHpjhPGuhP414ifcwjAi92swvm9Nq
    K3TvwQKBgA2oTkE2FBw9UfjSGo/uGK5Ctcy2N4AhCoc6pJU1DMuhTmAFlU600XoH
    d3RL1fupaK4dyAkxlAvyNfG6JbsPYa3EXOThnXhZHS6c8Fpe9UkcGpR+VSeCJGue
    lziHR3yn73gaK+sgNdZVbsW4jHACydlJYKLVlhcch6KkgeyIjgnz
    -----END RSA PRIVATE KEY-----
    """
#endif
 
/// GMJ---RSA并.p12加密解密
public class RSAEncryptor: NSObject {
    
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
    
    func getPrivateSecKey() -> SecKey? {
        let keyBase64 = Data(base64Encoded: kRSAPrivateKey.rsaCleanKey)!
        let sec = SecKeyCreateWithData(keyBase64 as CFData, [kSecAttrType: kSecAttrKeyTypeRSA,
                                                             kSecMatchBits: keyBase64.count * 8 ,
                                                             kSecReturnPersistentRef: true,
                                                             kSecAttrKeyClass: kSecAttrKeyClassPrivate] as NSDictionary, nil)
        return sec
    }

    func getPublicSecKey() -> SecKey? {
        let keyBase64 = Data(base64Encoded: kRSAPublicKey.rsaCleanKey)!
        let sec = SecKeyCreateWithData(keyBase64 as CFData, [kSecAttrType: kSecAttrKeyTypeRSA,
                                                   kSecMatchBits: keyBase64.count * 8 ,
                                                   kSecReturnPersistentRef: true,
                                                   kSecAttrKeyClass: kSecAttrKeyClassPublic] as NSDictionary, nil)
        return sec
    }
    
    // 使用'.12'私钥文件解密 11
    public func encryptData(data:Data, pubKey: String = kRSAPublicKey) throws -> Data {
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
    public func decryptData(data: [UInt8], privKey:String = kRSAPrivateKey) throws -> [UInt8] {
        let keyRef = getPublicSecKey()!
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
            //print("\(error?.takeRetainedValue())")
        }
        return ret
    }
}
