//
//  RSAEncryptor.swift
//  GIS2020
//
//  Created by boco on 2020/9/23.
//  Copyright © 2020 gemaojing. All rights reserved.
//

import Foundation
import Security

public let kRSAPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4YcP0lzql8Fgl3LP8xa/
    fl2SvkSf0MeAEZsrx+41bMRpHBa5mEM9is378/hKV6/kK3CadJFR6CF32AWWqqQ7
    0Dg6tOyD6PiXjHXnPV3pUOyzlI9DAeP/Ndcl+dJXYah5OjR3bCRGfrrn9Tl7tJQf
    qWdx7xKQZRvDuo7qHkOxa4U6eOqQkBGINTAktAr/RAZe6S1yZT9wBcSIzwJ0kCok
    I46rWUUuQb4md1rB/FO4/tCn+vYjW2erc0SyjC3ZsgjpGEAaAjv/AMGchC5BvTIS
    jBl8hWCH8ElVx2/NjASAGdU2XRWUwz2Etn4d8sxPJ5gVAAb5YsoE96Es3K+0LgGa
    cwIDAQAB
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
    
    
static func base64_encode_data(data:Data) -> String {
        let dataT =  data.base64EncodedData(options: .lineLength64Characters)//0
        let ret = String(data: dataT, encoding: .utf8) ?? "数据不存在"
        return ret
    }
    
static func bese64_decode(str:String) -> Data {
        let dateDefaule = "数据不存在".data(using: .utf8)! as Data
        let dataT:Data = Data(base64Encoded: str, options: .ignoreUnknownCharacters) ?? dateDefaule
        return dataT
    }
    
    // 使用'.12'私钥文件解密 11
    public func encryptData(data:Data, pubKey: String = kRSAPublicKey) throws -> Data {
        let keyRef = try PublicKey(pemEncoded: pubKey).reference
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
        let keyRef = try PrivateKey(pemEncoded: privKey).reference
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
    
    public func sign(data: [UInt8]) throws -> [UInt8] {
        let keyRef = try PrivateKey(pemEncoded: kRSAPrivateKey).reference
        return RSASign().RSASingNetCon(data: data, privateKey: keyRef) ?? []
    }
}









