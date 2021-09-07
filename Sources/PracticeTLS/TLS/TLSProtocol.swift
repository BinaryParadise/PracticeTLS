//
//  TLSProtocol.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation
import CryptoSwift

/// 报文类型
public enum TLSMessageType: UInt8 {
    case changeCipherSpec = 20
    case alert            = 21
    case handeshake       = 22
    case applicatonData   = 23
}

public struct TLSVersion: Comparable, RawRepresentable, CustomStringConvertible {
    
    public typealias RawValue = UInt16
    
    private var _rawValue: UInt16
    public var rawValue: UInt16 {
        get {
            return _rawValue
        }
    }
    
    public init(rawValue: UInt16) {
        _rawValue = rawValue
    }
    
    public static let Unknown = TLSVersion(rawValue: 0xfafa)
    public static let V1_0 = TLSVersion(rawValue: 0x0301)
    public static let V1_1 = TLSVersion(rawValue: 0x0302)
    public static let V1_2 = TLSVersion(rawValue: 0x0303)
    public static let V1_3 = TLSVersion(rawValue: 0x0304)
        
    public static func < (lhs: TLSVersion, rhs: TLSVersion) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
    
    public var description: String {
        switch self.rawValue {
        case Self.Unknown.rawValue:
            return "TLS Unknown"
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
    
    // TLS 1.3
    case helloRetryRequest  = 6
}

enum TLSExtensionType: UInt16 {
    case statusRequest = 0x0005
    case renegotiation_info = 0xff01
    case application_layer_protocol_negotiation = 0x0010
    case supported_versions = 0x002b
    case key_share = 0x0033
}

protocol TLSExtension: Streamable {
    var type: TLSExtensionType { get set }
}

func TLSExtensionsfromData(_ data: [UInt8]) -> [TLSExtension] {
    let stream = data.stream
    var exts: [TLSExtension] = []
    
    let ignoreExtension = {
        stream.readUInt16()
        if let length = stream.readUInt16() {
            stream.read(count: length)
        }
    }
    
    while !stream.endOfStream {
        if let b = stream.readUInt16(cursor: false) {
            if let type = TLSExtensionType(rawValue: b) {
                switch type {
                case .supported_versions:
                    exts.append(TLSSupportedVersionsExtension(stream: stream)!)
                case .key_share:
                    //启用TLS 1.3
                    #if false
                    exts.append(TLSKeyShareExtension(stream: stream, handshake: .clientHello)!)
                    #else
                    ignoreExtension()
                    #endif
                default:
                    ignoreExtension()
                }
            } else {
                ignoreExtension()
            }
        }
    }
    return exts
}

struct TLSSupportedVersionsExtension: Streamable, TLSExtension {
    var type: TLSExtensionType = .supported_versions
    var length: UInt16
    var versions: [TLSVersion] = []
    
    init() {
        versions.append(.V1_3)
        length = 2
    }
    
    init?(stream: DataStream) {
        type = TLSExtensionType(rawValue: stream.readUInt16()!)!
        length = stream.readUInt16() ?? 0
        let vers = DataStream(stream.read(count: Int(length))!, offset: 1)
        while !vers.endOfStream {
            versions.append(TLSVersion(rawValue: vers.readUInt16()!))
        }
    }
    
    func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: type.rawValue.bytes)
        bytes.append(contentsOf: length.bytes)
        bytes.append(contentsOf: versions.reduce([], { r, v in
            r + v.rawValue.bytes
        }))
        return bytes
    }
}

enum KeyShare {
    case clientHello([KeyShareEntry])
    case helloRetryRequest(NamedGroup)
    case serverHello(KeyShareEntry)
}

struct TLSKeyShareExtension: Streamable, TLSExtension {
    
    init?(stream: DataStream) {
        fatalError()
    }
    
    var type: TLSExtensionType = .key_share
    var keyShare: KeyShare
    
    init(keyShare: KeyShare) {
        self.keyShare = keyShare
    }
    
    init?(stream: DataStream, handshake: TLSHandshakeType) {
        type = TLSExtensionType(rawValue: stream.readUInt16()!)!
        let length = stream.readUInt16()!
        let entryStream = stream.read(count: length)!.stream
        switch handshake {
        case .clientHello:
            var entries: [KeyShareEntry] = []
            entryStream.read(count: 2)
            while !entryStream.endOfStream {
                if let entry = KeyShareEntry(stream: entryStream) {
                    entries.append(entry)
                }
            }
            keyShare = .clientHello(entries)
        case .helloRetryRequest:
            keyShare = .helloRetryRequest(.secp256r1)
        default:
            keyShare = .helloRetryRequest(.secp256r1)
        }
    }
    
    func entry(nameGroup: NamedGroup) -> KeyShareEntry? {
        switch keyShare {
        case .clientHello(let clientShares):
            return clientShares.first { e in
                e.group == nameGroup
            }
        case .helloRetryRequest(_):
            return nil
        case .serverHello(_):
            return nil
        }
    }
    
    func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: type.rawValue.bytes)
        switch keyShare {
        case .clientHello(clientShares: let clientShares):
            bytes.append(contentsOf: UInt16(clientShares.reduce(0, { r, entry in
                r + entry.dataWithBytes().count
            })).bytes)
            clientShares.forEach { entry in
                bytes.append(contentsOf: entry.dataWithBytes())
            }
        case .helloRetryRequest(selectedGroup: let selectedGroup):
            bytes.append(contentsOf: UInt16(selectedGroup.rawValue.bytes.count).bytes)
            bytes.append(contentsOf: selectedGroup.rawValue.bytes)
        case .serverHello(serverShare: let serverShare):
            bytes.append(contentsOf: UInt16(serverShare.dataWithBytes().count).bytes)
            bytes.append(contentsOf: serverShare.dataWithBytes())
        }
        return bytes
    }
}

struct KeyShareEntry: Streamable {
    var group: NamedGroup
    var keyExchange: [UInt8]
    
    init(group: NamedGroup, keyExchange: [UInt8]) {
        self.group = group
        self.keyExchange = keyExchange
    }
    
    init?(stream: DataStream) {
        guard let g = NamedGroup(rawValue: stream.readUInt16() ?? 0) else { return nil }
        group = g
        let length = stream.readUInt16() ?? 0
        keyExchange = stream.read(count: length) ?? []
    }
    
    func dataWithBytes() -> [UInt8] {
        return group.dataWithBytes() + UInt16(keyExchange.count).bytes + keyExchange
    }
}

extension Data {
    var bytes: [UInt8] {
        return [UInt8](self)
    }
}
