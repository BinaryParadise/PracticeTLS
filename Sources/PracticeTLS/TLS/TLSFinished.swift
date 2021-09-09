//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/24.
//

import Foundation

class TLSFinished: TLSHandshakeMessage {
    var verifyData: [UInt8]
    init(_ verifyData: [UInt8]) {
        self.verifyData = verifyData
        super.init(.finished)
    }
    
    override func dataWithBytes() -> [UInt8] {
        return messageData()
    }
    
    override func messageData() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: UInt(verifyData.count).bytes[1...3])
        bytes.append(contentsOf: verifyData)
        return bytes
    }
}
