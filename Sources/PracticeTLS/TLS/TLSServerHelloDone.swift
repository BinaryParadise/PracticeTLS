//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/9.
//

import Foundation

class TLSServerHelloDone: TLSHandshakeMessage {
    
    init() {
        super.init(.handshake(.serverHelloDone), context: nil)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes:[UInt8] = []
        //header
        bytes.append(type.rawValue) // 1 byte
        bytes.append(contentsOf: version.rawValue.bytes) // 2 bytes
        bytes.append(contentsOf: UInt16(4).bytes) // 2 bytes
                
        //body
        bytes.append(handshakeType.rawValue) // 1 byte
        bytes.append(contentsOf: UInt(0).bytes[1..<4]) //3 bytes
        return bytes
    }
}
