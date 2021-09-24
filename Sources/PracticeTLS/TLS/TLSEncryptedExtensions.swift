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
        super.init(.encryptedExtensions, context: context)
        context.record.serverCipherChanged = true
        nextMessage = TLSCertificate(context)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: UInt16.min.bytes)
        writeHeader(data: &bytes)
        return bytes
    }
}
