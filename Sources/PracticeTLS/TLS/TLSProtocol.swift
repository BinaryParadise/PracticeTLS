//
//  TLSProtocol.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation
import CryptoSwift

public enum ContentType: UInt8 {
    case changeCipherSpec = 20
    case alert            = 21
    case handeshake       = 22
    case applicatonData   = 23
}

/// 消息类型
public enum TLSMessageType {
    case changeCipherSpec
    case handshake(TLSHandshakeType)
    case alert
    case applicationData
    
    init(rawValue: UInt8) {
        guard let type = ContentType(rawValue: rawValue) else { fatalError("") }
        switch type {
        case .changeCipherSpec: self = .changeCipherSpec
        case .alert: self = .alert
        case .handeshake: self = .handshake(.clientHello)
        case .applicatonData: self = .applicationData
        }
    }
    
    var rawValue: UInt8 {
        switch self {
        case .changeCipherSpec:
            return ContentType.changeCipherSpec.rawValue
        case .handshake(_):
            return ContentType.handeshake.rawValue
        case .alert:
            return ContentType.alert.rawValue
        case .applicationData:
            return ContentType.applicatonData.rawValue
        }
    }
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

public enum TLSHandshakeType: UInt8 {
    // TLS 1.2
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
    case encryptedExtensions = 8
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

enum TLSMessageExtensionType {
    case clientHello
    case helloRetryRequest
    case serverHello
    case encryptedExtensions
    case certificate
    case certificateRequest
    case newSessionTicket
}

func TLSExtensionsfromData(_ data: [UInt8], messageType: TLSMessageExtensionType) -> [TLSExtension] {
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
                    let vers = TLSSupportedVersionsExtension(stream: stream)!
                    //启用TLS 1.3
                    #if true
                    exts.append(vers)
                    #endif
                case .key_share:
                    exts.append(TLSKeyShareExtension(stream: stream, messageType: messageType)!)
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

enum TLSKeyExchange {
    case rsa
    case ecdha(ECDHEncryptor)
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
    
    init?(stream: DataStream, messageType: TLSMessageExtensionType) {
        type = TLSExtensionType(rawValue: stream.readUInt16()!)!
        let length = stream.readUInt16()!
        let entryStream = stream.read(count: length)!.stream
        switch messageType {
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
            keyShare = .helloRetryRequest(.x25519)
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
        group = NamedGroup(rawValue: stream.readUInt16() ?? 0) ?? .reserved
        let length = stream.readUInt16() ?? 0
        keyExchange = stream.read(count: length) ?? []
    }
    
    func dataWithBytes() -> [UInt8] {
        return group.dataWithBytes() + UInt16(keyExchange.count).bytes + keyExchange
    }
}

extension Data {
    var uint8Array: [UInt8] {
        return [UInt8](self)
    }
}

enum TLS1_3 {}

extension TLS1_3 {
    static let tls1_3_prefix                        = [UInt8]("tls13 ".utf8)
    
    static let externalPSKBinderSecretLabel         = [UInt8]("ext binder".utf8)
    static let resumptionPSKBinderSecretLabel       = [UInt8]("res binder".utf8)
    static let clientEarlyTrafficSecretLabel        = [UInt8]("c e traffic".utf8)
    static let earlyExporterMasterSecretLabel       = [UInt8]("e exp master".utf8)

    static let clientHandshakeTrafficSecretLabel    = [UInt8]("c hs traffic".utf8)
    static let serverHandshakeTrafficSecretLabel    = [UInt8]("s hs traffic".utf8)
    static let clientApplicationTrafficSecretLabel  = [UInt8]("c ap traffic".utf8)
    static let serverApplicationTrafficSecretLabel  = [UInt8]("s ap traffic".utf8)
    static let exporterSecretLabel                  = [UInt8]("exp master".utf8)
    static let resumptionMasterSecretLabel          = [UInt8]("res master".utf8)
    static let finishedLabel                        = [UInt8]("finished".utf8)
    static let derivedLabel                         = [UInt8]("derived".utf8)
    static let resumptionLabel                      = [UInt8]("resumption".utf8)

    static let clientCertificateVerifyContext       = [UInt8]("TLS 1.3, client CertificateVerify".utf8)
    static let serverCertificateVerifyContext       = [UInt8]("TLS 1.3, server CertificateVerify".utf8)
    
    class HandshakeState {
        var preSharedKey: [UInt8]?
        var earlySecret: [UInt8]?
        var clientEarlyTrafficSecret: [UInt8]?
        var handshakeSecret: [UInt8]?
        var clientHandshakeTrafficSecret: [UInt8]?
        var serverHandshakeTrafficSecret: [UInt8]?
        var masterSecret: [UInt8]?
        var clientTrafficSecret: [UInt8]?
        var serverTrafficSecret: [UInt8]?
        var sessionResumptionSecret: [UInt8]?
        var resumptionBinderSecret: [UInt8]?
        var selectedIdentity: UInt16?
    }
}
