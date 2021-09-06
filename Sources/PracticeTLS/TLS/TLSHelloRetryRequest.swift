//
//  TLSHelloRetryRequest.swift
//  
//
//  Created by Rake Yang on 2021/9/3.
//

import Foundation
import CryptoSwift

public class TLSHelloRetryRequest: TLSHandshakeMessage {
    var random: [UInt8]
    var sessionID: [UInt8]?
    var cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = []
    
    init(client: TLSClientHello) {
        random = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        ]
        super.init()

        handshakeType = .serverHello
        sessionID = client.sessionID
        cipherSuite = .TLS_AES_128_CCM_SHA256
        
        extensions.append(TLSSupportedVersionsExtension())
        extensions.append(TLSKeyShareExtension(keyShare: .helloRetryRequest(selectedGroup: NamedGroup.secp256r1)))
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    override func dataWithBytes() -> [UInt8] {
        contentLength = 6
        contentLength += UInt16(random.count)
        contentLength += 1
        contentLength += UInt16(sessionID?.count ?? 0)
        contentLength += 2+1
        
        let extBytes = extensions.reduce([], { r, ext in
            r + ext.dataWithBytes()
        })
        
        if extBytes.count > 0 {
            contentLength += 2
            contentLength += UInt16(extBytes.count)
        }
        
        var bytes: [UInt8] = []
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        bytes.append(contentsOf: contentLength.bytes) // 2 bytes
        
        //内容
        bytes.append(handshakeType.rawValue) // 1 byte
        bytes.append(contentsOf: UInt(contentLength-4).bytes[1...]) // 3 bytes
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        
        bytes.append(contentsOf: random) // 32 bytes
        
        bytes.append(UInt8(sessionID?.count ?? 0)) // 1 byte
        bytes.append(contentsOf: sessionID ?? [])
        
        bytes.append(contentsOf: cipherSuite.rawValue.bytes) // 2 bytes
        bytes.append(compressionMethod.rawValue) // 1 byte
        
        if extBytes.count > 0 {
            bytes.append(contentsOf: UInt16(extBytes.count).bytes) // 2 bytes
            bytes.append(contentsOf: extBytes) // x bytes
        }
        
        return bytes
    }
}
