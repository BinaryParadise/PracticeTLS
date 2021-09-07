//
//  TLSClientHello.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSClientHello: TLSHandshakeMessage {
    
    /// 握手数据长度（不包括握手协议头：类型、长度）
    var bodyLength: Int = 0
    var clientVersion: TLSVersion
    var random: Random
    var sessionID: [UInt8]?
    var cipherSuites: [CipherSuite] = []
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = []
    var keyExchange: [UInt8] {
        return (extend(.key_share) as? TLSKeyShareExtension)?.entry(nameGroup: .secp256r1)?.keyExchange ?? []
    }

    required init?(stream: DataStream) {
        stream.position = 5
        let _handshakeType = TLSHandshakeType(rawValue: stream.readByte()!)!
        bodyLength = stream.readUInt24() ?? 0
        clientVersion = TLSVersion(rawValue: stream.readUInt16() ?? 0)
        random = Random(stream: (stream.read(count: 32) ?? []).stream)
        if let len = stream.readByte(), len > 0 {
            sessionID = stream.read(count: Int(len))
        }
        if let cipherLen = stream.readUInt16() {
            if let bytes = stream.read(count: Int(cipherLen)) {
                let cipherS = DataStream(Data(bytes))
                while true {
                    if let item = cipherS.readUInt16() {
                        if let suite = CipherSuite(rawValue: item) {
                            cipherSuites.append(suite)
                        } else {
                            //print("\(String(format: "unsupport cipher suite: 0x%0X", item))")
                        }
                    } else {
                        break
                    }
                }
            }
        }
        if let len = stream.readByte(), let method = stream.read(count: Int(len))?.first {
            compressionMethod = CompressionMethod(rawValue: method) ?? .null
        }
        if let extLen = stream.readUInt16(), let bytes = stream.read(count: Int(extLen)) {
            extensions = TLSExtensionsfromData(bytes)
        }
        super.init(stream: DataStream(stream.data))
        handshakeType = _handshakeType
    }
    
    func extend(_ type: TLSExtensionType) -> TLSExtension? {
        return extensions.first { ext in
            ext.type == type
        }
    }
    
    public override func responseMessage() -> TLSHandshakeMessage? {
        if (extend(.supported_versions) as? TLSSupportedVersionsExtension)?.versions.contains(.V1_3) != nil {
            if keyExchange.count == 0 {
                return TLSHelloRetryRequest(client: self)
            }
        }
        let serverHello = TLSServerHello(client: self)
        return serverHello
    }
}
