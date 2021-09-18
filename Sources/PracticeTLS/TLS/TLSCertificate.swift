//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/9.
//

import Foundation
import SecurityRSA

extension Bundle {
    class func certBundle() -> Bundle {
        return Bundle(path: "\(Bundle(for: TLSCertificate.self).resourcePath ?? "")/PracticeTLSTool_PracticeTLS.bundle") ?? .main
    }
}

public class TLSCertificate: TLSHandshakeMessage {
    
    init(_ context: TLSConnection? = nil) {
        super.init(.handshake(.certificate), context: context)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var certificateData: [UInt8] = []
        
        let negotiatedProtocolVersion = context?.negotiatedProtocolVersion ?? .V1_2
        if negotiatedProtocolVersion == .V1_3 {
            certificateData.append(0)
        }

        var certificatesList: [UInt8] = []
        for certificate in TLSSessionManager.shared.identity!.certificateChain {
            let certificateData = certificate.data
            certificatesList.append(contentsOf: UInt(certificateData.count).bytes[1...3])
            certificatesList.append(contentsOf: certificateData)
            
            if negotiatedProtocolVersion == .V1_3 {
                certificatesList.append(contentsOf: UInt16(0).bytes)
            }
        }
        certificateData.append(contentsOf: UInt(certificatesList.count).bytes[1...3])
        certificateData.append(contentsOf: certificatesList)
        
        var bytes: [UInt8] = []
        //header
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        bytes.append(contentsOf: UInt16(certificateData.count + 4).bytes) // 2 bytes

        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: UInt(certificateData.count).bytes[1...3])
        bytes.append(contentsOf: certificateData)
        return bytes
    }
}
