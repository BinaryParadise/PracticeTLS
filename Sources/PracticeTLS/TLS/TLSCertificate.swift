//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/9.
//

import Foundation

extension Bundle {
    class func certBundle() -> Bundle {
        return Bundle(path: "\(Bundle(for: TLSCertificate.self).resourcePath ?? "")/PracticeTLS_SimpleHTTPServer.bundle") ?? .main
    }
}

public class TLSCertificate: TLSHandshakeMessage {
    
    init(_ context: TLSConnection? = nil) {
        super.init(.certificate, context: context)
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
        
        writeHeader(data: &certificateData)
        return certificateData
    }
}
