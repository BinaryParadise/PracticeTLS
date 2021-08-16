//
//  TLSEncryptedMessage.swift
//  
//
//  Created by Rake Yang on 2021/8/12.
//

import Foundation

class TLSEncryptedMessage: TLSHandshakeMessage {
    var message: [UInt8] = []
    
    override init() {
        super.init()
        version = .V1_2
    }
    
    required init?(stream: DataStream) {
        stream.position = 5
        message = stream.readToEnd() ?? []
        super.init(stream: DataStream(stream.data))
    }
    
    override func dataWithBytes() -> Data {
        var data = Data()
        data.append(type.rawValue)
        data.append(contentsOf: version.rawValue.bytes())
        data.append(contentsOf: UInt16(message.count).bytes())
        data.append(contentsOf: message)
        return data
    }
}
