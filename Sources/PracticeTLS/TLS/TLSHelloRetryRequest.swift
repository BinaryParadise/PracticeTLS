//
//  TLSHelloRetryRequest.swift
//  
//
//  Created by Rake Yang on 2021/9/3.
//

import Foundation
import CryptoSwift

let helloRetryRequestRandom: [UInt8] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
]

public class TLSHelloRetryRequest: TLSHandshakeMessage {
    var random: [UInt8] = helloRetryRequestRandom
    var sessionID: [UInt8]?
    var cipherSuite: CipherSuite = .TLS_AES_128_GCM_SHA256
    var compressionMethod: CompressionMethod = .null
    var extensions: [TLSExtension] = []
    
    init(client: TLSClientHello, context: TLSConnection) {
        super.init(.serverHello)

        sessionID = client.sessionID
        
        selectedCurve = .secp256r1
        extensions.append(TLSSupportedVersionsExtension(.V1_3))
        extensions.append(TLSKeyShareExtension(keyShare: .helloRetryRequest(selectedCurve)))
        
        context.record = TLS1_3.RecordLayer(context)
        context.record.setPendingSecurityParametersForCipherSuite(cipherSuite)
    }
    
    public override init?(stream: DataStream, context: TLSConnection) {
        fatalError("init(stream:context:) has not been implemented")
    }
    
    override func dataWithBytes() -> [UInt8] {
        let extBytes = extensions.reduce([], { r, ext in
            r + ext.dataWithBytes()
        })
        
        var bytes: [UInt8] = []
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        bytes.append(contentsOf: random) // 32 bytes
        bytes.append(UInt8(sessionID?.count ?? 0)) // 1 byte
        bytes.append(contentsOf: sessionID ?? []) // x bytes
        bytes.append(contentsOf: cipherSuite.rawValue.bytes) // 2 bytes        
        bytes.append(compressionMethod.rawValue) // 1 byte
        
        if extBytes.count > 0 {
            bytes.append(contentsOf: UInt16(extBytes.count).bytes) // 2 bytes
            bytes.append(contentsOf: extBytes) // x bytes
        }
        writeHeader(data: &bytes)
        return bytes
    }
}
