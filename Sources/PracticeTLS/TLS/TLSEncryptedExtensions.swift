//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/10.
//

import Foundation

class TLSEncryptedExtensions: TLSHandshakeMessage {
    init() {
        super.init(.encryptedExtensions)
        
        nextMessage = TLSCertificate()
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: UInt16(0).bytes)
        return bytes
    }
}
