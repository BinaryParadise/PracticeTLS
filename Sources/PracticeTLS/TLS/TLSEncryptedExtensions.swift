//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/10.
//

import Foundation
import SecurityRSA

class TLSEncryptedExtensions: TLSHandshakeMessage {
    
    init(context: TLSConnection) {
        super.init(.handshake(.encryptedExtensions), context: context)
        context.record.serverCipherChanged = true
        nextMessage = TLSCertificate(context)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(type.rawValue)
        bytes.append(contentsOf: version.rawValue.bytes)
        bytes.append(contentsOf: UInt16(6).bytes)
        
        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: 2.bytes[1...])
        bytes.append(contentsOf: UInt16.min.bytes)
        return bytes
    }
}
