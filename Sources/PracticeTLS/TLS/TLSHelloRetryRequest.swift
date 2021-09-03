//
//  TLSHelloRetryRequest.swift
//  
//
//  Created by Rake Yang on 2021/9/3.
//

import Foundation
import CryptoSwift

public class TLSHelloRetryRequest: TLSHandshakeMessage {
    
    /// 握手数据长度（不包括握手协议头：类型、长度）
    var bodyLength: Int = 0
    var random: [UInt8]
    var sessionID: [UInt8]?
    var cipherSuite: CipherSuite = .TLS_AES_128_CCM_SHA256
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = []
    
    init(client: TLSClientHello) {
        random = AES.randomIV(32)
        super.init()

        handshakeType = .helloRetryRequest
        sessionID = client.sessionID
        cipherSuite = .TLS_AES_128_CCM_SHA256
        
        extensions.append(TLSSupportedVersionsExtension())
        extensions.append(TLSKeyShareExtension(keyShare: .helloRetryRequest(selectedGroup: NamedGroup.secp256r1)))
        
        contentLength = UInt16(6+random.count)
        if let s = sessionID {
            bodyLength += 1 + s.count
        }
        contentLength += 3+4
        contentLength += UInt16(extensions.reduce(0, { r, ext in
            r + ext.dataWithBytes().count
        }))
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(type.rawValue)
        bytes.append(contentsOf: version.rawValue.bytes)
        bytes.append(contentsOf: contentLength.bytes)
        
        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: UInt(contentLength-5).bytes[1...])
        bytes.append(contentsOf: version.rawValue.bytes)
        if let s = sessionID {
            bytes.append(UInt8(32))
            bytes.append(contentsOf: s)
        }
        bytes.append(contentsOf: cipherSuite.rawValue.bytes)
        bytes.append(UInt8(1))
        bytes.append(compressionMethod.rawValue)
        bytes.append(contentsOf: UInt16(extensions.reduce(0, { r, ext in
            r + ext.dataWithBytes().count
        })).bytes)
        bytes.append(contentsOf: extensions.reduce([], { r, ext in
            r + ext.dataWithBytes()
        }))
        return bytes
    }
}
