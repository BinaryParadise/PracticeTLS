//
//  TLSUtilities.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

class Random: Equatable {
    var gmtUnixTime: UInt32
    var randomBytes: [UInt8]
    
    var bytes: [UInt8] {
        return self.gmtUnixTime.bigEndianBytes + randomBytes
    }
    
    init() {
        randomBytes = TLSRandomBytes(count: 28)
        gmtUnixTime = UInt32(Date().timeIntervalSinceReferenceDate)
    }
    
    init(_ bytes: [UInt8]) {
        let stream = DataStream(bytes: bytes)
        gmtUnixTime = UInt32(bigEndianBytes: bytes[0..<4])!
        randomBytes = stream.readToEnd() ?? []
    }
        
    static func == (lhs: Random, rhs: Random) -> Bool {
        return lhs.gmtUnixTime == rhs.gmtUnixTime && lhs.randomBytes == rhs.randomBytes
    }
}

public enum TLSError : Error
{
    case error(String)
}

enum CipherSuite: UInt16 {
    //TLS 1.2
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  = 0xc02f
    /// 密钥交换算法 + 签名算法 + 对称加密算法 + 摘要算法
    case TLS_RSA_WITH_AES_128_GCM_SHA256        = 0x009c
}

enum CompressionMethod: UInt8 {
    case null = 0
}

typealias HMACFunction = (_ secret : [UInt8], _ data : [UInt8]) -> [UInt8]
public enum MACAlgorithm {
    //    case null
    case hmac_md5
    case hmac_sha1
    case hmac_sha256
    case hmac_sha384
    case hmac_sha512
    
    var size: Int {
        get {
            switch self {
                //            case .null:
                //                fatalError("Null MAC has no size")
                
            case .hmac_md5:
                return 16
                
            case .hmac_sha1:
                return 20
                
            case .hmac_sha256:
                return 32
                
            case .hmac_sha384:
                return 48
                
            case .hmac_sha512:
                return 64
                
            }
        }
    }
    
    var hmacFunction: HMACFunction {
        switch self {
        case .hmac_md5:
            return HMAC_MD5
            
        case .hmac_sha1:
            return HMAC_SHA1
            
        case .hmac_sha256:
            return HMAC_SHA256
            
        case .hmac_sha384:
            return HMAC_SHA384
            
        case .hmac_sha512:
            return HMAC_SHA512
        }
    }
}

/// XOR
func ^(lhs: [UInt8], rhs: [UInt8]) -> [UInt8]
{
    let minimum = min(rhs.count, lhs.count)
    
    var result = [UInt8](repeating: 0, count: minimum)
    
    for i in 0..<minimum {
        result[i] = lhs[i] ^ rhs[i]
    }
    
    return result
}

public extension String {
    static func fromUTF8Bytes(_ bytes : [UInt8]) -> String? {
        return bytes.withUnsafeBufferPointer { buffer in
            var string  = ""
            let hadError = transcode(buffer.makeIterator(), from: UTF8.self, to: UTF32.self, stoppingOnError: false) { string.append(Character(UnicodeScalar($0)!)) }
            
            if !hadError {
                return string
            }
            
            return nil
        }
    }
}
