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
        super.init(.encryptedExtensions)
        
        let cert = TLSCertificate()
                
//        var proofData = [UInt8](repeating: 0x20, count: 64)
//        proofData += [UInt8]("TLS 1.3, server CertificateVerify".utf8)
//        proofData += [0]
//        proofData += context.transcriptHash
//        let signed = try? RSAEncryptor().sign(data: proofData)
//        cert.nextMessage = TLSCertificateVerify(algorithm: .rsa_pkcs1_sha256, signature: signed ?? [])
        cert.nextMessage = context.verifyDataForFinishedMessage(isClient: false)
        nextMessage = cert
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
