//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/9.
//

import Foundation

extension Bundle {
    class func certBundle() -> Bundle {
        return Bundle(path: "\(Bundle(for: TLSCertificate.self).resourcePath ?? "")/PracticeTLSTool_PracticeTLS.bundle") ?? .main
    }
}

public class TLSCertificate: TLSHandshakeMessage {
    
    override init(_ type: TLSHandshakeType = .clientHello) {
        super.init(.certificate)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var certificateData: [UInt8] = []

        var certificatesList: [UInt8] = []
        for certificate in TLSSessionManager.shared.identity!.certificateChain {
            let certificateData = certificate.data
            certificatesList.append(contentsOf: UInt(certificateData.count).bytes[1...3])
            certificatesList.append(contentsOf: certificateData)
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
