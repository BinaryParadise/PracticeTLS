//
//  TLSProtocol.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

/// 报文类型
enum TLSMessageType: UInt8 {
    case changeCipherSpec = 20
    case alert            = 21
    case handeshake       = 22
    case applicatonData   = 23
}

struct TLSVersion: Comparable {
    
    public typealias RawValue = UInt16
    
    private var _rawValue: UInt16
    public var rawValue: UInt16 {
        get {
            return _rawValue
        }
    }
    
    init(rawValue: UInt16) {
        _rawValue = rawValue
    }
    
    public static let V1_0 = TLSVersion(rawValue: 0x0301)
    public static let V1_1 = TLSVersion(rawValue: 0x0302)
    public static let V1_2 = TLSVersion(rawValue: 0x0303)
    public static let V1_3 = TLSVersion(rawValue: 0x0304)
        
    static func < (lhs: TLSVersion, rhs: TLSVersion) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
    
    public var description: String {
        switch self.rawValue {
        case Self.V1_0.rawValue:
            return "TLS v1.0（RFC 2246）"
        case Self.V1_1.rawValue:
            return "TLS v1.1（RFC 4346）"
        case Self.V1_2.rawValue:
            return "TLS v1.2（RFC 5246）"
        case Self.V1_3.rawValue:
            return "TLS v1.3（RFC 8446）"
        default:
            return "Unknown TLS version \(_rawValue >> 8).\(_rawValue & 0xff)"
        }
    }
}

enum TLSHandshakeType: UInt8 {
     case helloRequest          = 0
     case clientHello           = 1
     case serverHello           = 2
     case certificate           = 11
     case serverKeyExchange     = 12
     case certificateRequest    = 13
     case serverHelloDone       = 14
     case certificateVerify     = 15
     case clientKeyExchange     = 16
     case finished              = 20
}

enum TLSExtensionType: UInt16 {
    case statusRequest = 0x0005
}

struct TLSExtension {
    var type: TLSExtensionType
    var length: UInt16
    
    var bytes: [UInt8] {
        return type.rawValue.bytes() + length.bytes()
    }
}
