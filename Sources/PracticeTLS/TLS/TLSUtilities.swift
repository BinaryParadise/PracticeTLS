//
//  TLSUtilities.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

class Random: Equatable, Streamable {
    var gmtUnixTime: UInt32
    var randomBytes: [UInt8]
    
    init() {
        randomBytes = TLSRandomBytes(count: 28)
        gmtUnixTime = UInt32(Date().timeIntervalSinceReferenceDate)
    }
    
    init(_ bytes: [UInt8]) {
        let stream = DataStream(bytes)
        gmtUnixTime = UInt32(bigEndianBytes: stream.read(count: 4) ?? [])!
        randomBytes = stream.read(count: 28) ?? []
    }
        
    static func == (lhs: Random, rhs: Random) -> Bool {
        return lhs.gmtUnixTime == rhs.gmtUnixTime && lhs.randomBytes == rhs.randomBytes
    }
    
    func dataWithBytes() -> [UInt8] {
        return self.gmtUnixTime.bigEndianBytes + randomBytes
    }
}

public enum TLSError : Error
{
    case error(String)
}

enum CipherSuite: UInt16 {
    /// 密钥交换算法 + 签名算法 + 对称加密算法 + 摘要算法
    case TLS_RSA_WITH_AES_256_CBC_SHA           = 0x35
    case TLS_RSA_WITH_AES_256_CBC_SHA256        = 0x3d
    case TLS_RSA_WITH_AES_128_GCM_SHA256        = 0x009c
    
    var description: String {
        switch self {
        case .TLS_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_RSA_WITH_AES_256_CBC_SHA"
        case .TLS_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_RSA_WITH_AES_256_CBC_SHA256"
        case .TLS_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_RSA_WITH_AES_128_GCM_SHA256"
        }
    }
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

/// P_hash function as defined in RFC 2246, section 5, p. 11
func P_hash(_ hmacFunction : HMACFunction, secret : [UInt8], seed : [UInt8], outputLength : Int) -> [UInt8]
{
    var outputData = [UInt8]()
    var A : [UInt8] = seed
    var bytesLeftToWrite = outputLength
    while (bytesLeftToWrite > 0)
    {
        A = hmacFunction(secret, A)
        let output = hmacFunction(secret, A + seed)
        let bytesFromOutput = min(bytesLeftToWrite, output.count)
        outputData.append(contentsOf: output[0..<bytesFromOutput])
        
        bytesLeftToWrite -= bytesFromOutput
    }
    
    return outputData
}
