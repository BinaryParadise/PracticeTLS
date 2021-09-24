//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/9.
//

import Foundation

class TLSServerHelloDone: TLSHandshakeMessage {
    
    init() {
        super.init(.serverHelloDone, context: nil)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes:[UInt8] = []
        writeHeader(data: &bytes)
        return bytes
    }
}
