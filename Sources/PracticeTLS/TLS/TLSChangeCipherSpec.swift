//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/12.
//

import Foundation

class TLSChangeCipherSpec: TLSMessage {
    var isClient: Bool = false
    
    override init(_ type: TLSMessageType = .handeshake) {
        super.init(.changeCipherSpec)
    }
    
    override init?(stream: DataStream, context: TLSConnection) {        
        isClient = true
        super.init(.changeCipherSpec)
    }
    
    override func dataWithBytes() -> [UInt8] {
        var data: [UInt8] = []
        data.append(type.rawValue)
        data.append(contentsOf: version.rawValue.bytes)
        data.append(contentsOf: UInt16(1).bytes)
        data.append(0x01)
        return data
    }
}
