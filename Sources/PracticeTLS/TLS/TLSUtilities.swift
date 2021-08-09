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

enum CipherSuite: UInt16 {
    case TLS_NULL_WITH_NULL_NULL                = 0x0000
    case TLS_RSA_WITH_NULL_MD5                  = 0x0001
    case TLS_RSA_WITH_NULL_SHA                  = 0x0002
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5         = 0x0003
    case TLS_RSA_WITH_RC4_128_MD5               = 0x0004
    case TLS_RSA_WITH_RC4_128_SHA               = 0x0005
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5     = 0x0006
    case TLS_RSA_WITH_IDEA_CBC_SHA              = 0x0007
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA      = 0x0008
    case TLS_RSA_WITH_DES_CBC_SHA               = 0x0009
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA          = 0x000A
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA   = 0x000B
    case TLS_DH_DSS_WITH_DES_CBC_SHA            = 0x000C
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA       = 0x000D
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA   = 0x000E
    case TLS_DH_RSA_WITH_DES_CBC_SHA            = 0x000F
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA       = 0x0010
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x0011
    case TLS_DHE_DSS_WITH_DES_CBC_SHA           = 0x0012
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA      = 0x0013
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x0014
    case TLS_DHE_RSA_WITH_DES_CBC_SHA           = 0x0015
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0016
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5     = 0x0017
    case TLS_DH_anon_WITH_RC4_128_MD5           = 0x0018
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA  = 0x0019
    case TLS_DH_anon_WITH_DES_CBC_SHA           = 0x001A
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA      = 0x001B
    
    case TLS_KRB5_WITH_DES_CBC_SHA              = 0x001E
    case TLS_KRB5_WITH_3DES_EDE_CBC_SHA         = 0x001F
    case TLS_KRB5_WITH_RC4_128_SHA              = 0x0020
    case TLS_KRB5_WITH_IDEA_CBC_SHA             = 0x0021
    case TLS_KRB5_WITH_DES_CBC_MD5              = 0x0022
    case TLS_KRB5_WITH_3DES_EDE_CBC_MD5         = 0x0023
    case TLS_KRB5_WITH_RC4_128_MD5              = 0x0024
    case TLS_KRB5_WITH_IDEA_CBC_MD5             = 0x0025
    
    //TLS 1.1
    case TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA    = 0x0026
    case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA    = 0x0027
    case TLS_KRB5_EXPORT_WITH_RC4_40_SHA        = 0x0028
    case TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5    = 0x0029
    case TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5    = 0x002A
    case TLS_KRB5_EXPORT_WITH_RC4_40_MD5        = 0x002B
    case TLS_RSA_WITH_AES_128_CBC_SHA           = 0x002F
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA        = 0x0030
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA        = 0x0031
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA       = 0x0032
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA       = 0x0033
    case TLS_DH_anon_WITH_AES_128_CBC_SHA       = 0x0034
    case TLS_RSA_WITH_AES_256_CBC_SHA           = 0x0035
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA        = 0x0036
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA        = 0x0037
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA       = 0x0038
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA       = 0x0039
    case TLS_DH_anon_WITH_AES_256_CBC_SHA       = 0x003A
    
    //TLS 1.2
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA256     = 0x003E
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA256     = 0x003F
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256    = 0x0040
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256    = 0x0067
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA256     = 0x0068
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA256     = 0x0069
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256    = 0x006A
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256    = 0x006B
    
    //TLS 1.3
    case TLS_AES_128_GCM_SHA256                 = 0x1301
    case TLS_AES_256_GCM_SHA384                 = 0x1302
    case TLS_CHACHA20_POLY1305_SHA256           = 0x1303
    case TLS_AES_128_CCM_SHA256                 = 0x1304
    case TLS_AES_128_CCM_8_SHA256               = 0x1305
    
    //TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  = 0xC023
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  = 0xC024
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256   = 0xC025
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384   = 0xC026
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    = 0xC027
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    = 0xC028
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256     = 0xC029
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384     = 0xC02A
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  = 0xC02B
    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  = 0xC02C
    case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256   = 0xC02D
    case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384   = 0xC02E
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    = 0xC02F
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    = 0xC030
    case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256     = 0xC031
    case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384     = 0xC032
}

enum CompressionMethod: UInt8 {
    case null = 0
}
