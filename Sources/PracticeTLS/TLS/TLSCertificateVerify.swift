//
//  TLSCertificateVerify.swift
//  
//
//  Created by Rake Yang on 2021/9/14.
//

import Foundation

public enum TLSSignatureScheme : UInt16 {
    /* RSASSA-PKCS1-v1_5 algorithms */
    case rsa_pkcs1_sha1 = 0x0201
    case rsa_pkcs1_sha256 = 0x0401
    case rsa_pkcs1_sha384 = 0x0501
    case rsa_pkcs1_sha512 = 0x0601
    
    /* ECDSA algorithms */
    case ecdsa_secp256r1_sha256 = 0x0403
    case ecdsa_secp384r1_sha384 = 0x0503
    case ecdsa_secp521r1_sha512 = 0x0603
    
    /* RSASSA-PSS algorithms */
    case rsa_pss_sha256 = 0x0804
    case rsa_pss_sha384 = 0x0805
    case rsa_pss_sha512 = 0x0806
    
    /* EdDSA algorithms */
    case ed25519 = 0x0807
    case ed448 = 0x0808
}
    
class TLSCertificateVerify: TLSHandshakeMessage {
    let algorithm: TLSSignatureScheme
    let signature: [UInt8]
    
    init(algorithm: TLSSignatureScheme, signature: [UInt8])
    {
        self.algorithm = algorithm
        self.signature = signature
        
        super.init(.certificateVerify)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(type.rawValue)
        bytes.append(contentsOf: version.rawValue.bytes)
        bytes.append(contentsOf: UInt16(signature.count-4).bytes)
        
        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: signature.count.bytes[1...])
        bytes.append(contentsOf: signature)
        return bytes
    }
}
