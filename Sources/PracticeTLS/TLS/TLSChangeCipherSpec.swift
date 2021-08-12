//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/12.
//

import Foundation

class TLSChangeCipherSpec: TLSHandshakeMessage {
    var encryptedMessage: TLSEncryptedMessage?
    override init() {
        super.init()
        type = .changeCipherSpec
        version = .V1_2
        contentLength = 1
    }
    
    required init?(stream: DataStream) {
        fatalError("init(stream:) has not been implemented")
    }
    
    override func dataWithBytes() -> Data {
        var data: [UInt8] = []
        data.append(type.rawValue)
        data.append(contentsOf: version.rawValue.bytes())
        data.append(contentsOf: contentLength.bytes())
        data.append(0x01)
        
        if let em = encryptedMessage {
            data.append(contentsOf: em.dataWithBytes().bytes)
        }
        return Data(data)
    }
}
