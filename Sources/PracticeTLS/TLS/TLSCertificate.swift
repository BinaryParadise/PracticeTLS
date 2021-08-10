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
    var certData: Data = Data()
    var bodyLength: Int = 0
    var certsLength: Int = 0
    override init() {
        super.init()
        
        handshakeType = .certificate
        if let certPath = Bundle.certBundle().path(forResource: "Cert/localhost.cer", ofType: nil) {
            if let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)) {
                self.certData = certData
                contentLength = UInt16(certData.count + 4 + 3 + 3)
                bodyLength = Int(contentLength - 4)
                certsLength = bodyLength - 3
            }
        }
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    override func dataWithBytes() -> Data {
        var bytes = Data()
        //header
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes()) // 2 bytes
        bytes.append(contentsOf: UInt16(contentLength).bytes()) // 2 bytes
        
        //body
        bytes.append(handshakeType.rawValue) // 1 byte
        bytes.append(contentsOf: UInt(bodyLength).bytes()[1..<4]) //3 bytes
        bytes.append(contentsOf: UInt(certsLength).bytes()[1..<4]) //3 bytes
        bytes.append(contentsOf: UInt(certsLength-3).bytes()[1..<4]) // 3 bytes
        bytes.append(certData) //x bytes
        return bytes
    }
}
