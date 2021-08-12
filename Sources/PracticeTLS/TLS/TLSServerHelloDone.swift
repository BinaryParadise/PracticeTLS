//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/9.
//

import Foundation

class TLSServerHelloDone: TLSHandshakeMessage {
    var bodyLength: Int = 0
    override init() {
        super.init()
        
        contentLength = 4
        handshakeType = .serverHelloDone
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    override func dataWithBytes() -> Data {
        var bytes = TLSCertificate().dataWithBytes()
        //header
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes()) // 2 bytes
        bytes.append(contentsOf: UInt16(contentLength).bytes()) // 2 bytes
        
        //bytes.append(contentsOf: TLSServerKeyExchange().dataWithBytes())
        
        //body
        bytes.append(handshakeType.rawValue) // 1 byte
        bytes.append(contentsOf: UInt(bodyLength).bytes()[1..<4]) //3 bytes
        return bytes
    }
}
