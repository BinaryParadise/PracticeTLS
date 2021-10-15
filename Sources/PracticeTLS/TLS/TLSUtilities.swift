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
        
    required init(stream: DataStream) {
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

/// [密钥交换算法] + 签名算法 + 对称加密算法 + 摘要算法
public enum CipherSuite: UInt16 {
    case TLS_RSA_WITH_AES_128_GCM_SHA256        = 0x009c
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  = 0xc02f
    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8

    
    // TLS 1.3 cipher suites.
    // The key exchange method is no longer part of the cipher suite, so
    // these can't be used for TLS 1.2 and TLS 1.2 cipher suites can't
    // be used for TLS 1.3 either.
    case TLS_AES_128_GCM_SHA256 = 0x1301
    case TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    
    public var description: String {
        switch self {
        case .TLS_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_RSA_WITH_AES_128_GCM_SHA256"
        default:
            return "\(self)"
        }
    }
}

enum CompressionMethod: UInt8 {
    case null = 0
}

public enum KeyExchangeAlgorithm
{
    case rsa
    case dhe
    case ecdhe
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
    
    var bytes: [UInt8] {
        return data(using: .utf8)?.bytes ?? []
    }
    
    var uint8Array: [UInt8] {
        var result: [UInt8] = []
        var even: Bool = true
        var byte: UInt8 = 0
        func decodeByte(c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x41...0x46: return c - 0x41 + 10
            case 0x61...0x66: return c - 0x61 + 10
            default:
                return nil
            }
        }
        for c in utf8 {
            guard let val = decodeByte(c: c) else { continue }
            if even {
                byte = val << 4
            } else {
                byte += val
                result.append(byte)
            }
            even = !even
        }
        return result
    }
    
    var rsaCleanKey: String {
        if contains("BEGIN") {
            var arr = self.split(separator: "\n")
            arr.removeFirst()
            arr.removeLast()
            return arr.joined()
        }
        return self
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
