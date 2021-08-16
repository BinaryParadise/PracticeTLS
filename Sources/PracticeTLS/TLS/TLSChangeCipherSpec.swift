//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/12.
//

import Foundation

class TLSChangeCipherSpec: TLSHandshakeMessage {
    var isClient: Bool = false
    override init() {
        super.init()
        type = .changeCipherSpec
        version = .V1_2
        contentLength = 1
    }
    
    required init?(stream: DataStream) {
        isClient = true
        super.init(stream: stream)
    }
    
    override func dataWithBytes() -> Data {
        var data: [UInt8] = []
        data.append(type.rawValue)
        data.append(contentsOf: version.rawValue.bytes())
        data.append(contentsOf: contentLength.bytes())
        data.append(0x01)
        return Data(data)
    }
}
