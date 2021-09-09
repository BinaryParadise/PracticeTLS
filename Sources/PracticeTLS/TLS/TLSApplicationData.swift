//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/25.
//

import Foundation

class TLSApplicationData: TLSMessage {
    var encryptedData: [UInt8] = []
    init(_ data: [UInt8]) {
        encryptedData = data
        super.init(.applicatonData)
    }
    
    override init?(stream: DataStream, context: TLSConnection) {
        super.init(stream: stream, context: context)
        encryptedData = stream.readToEnd() ?? []
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(type.rawValue)
        bytes.append(contentsOf: version.rawValue.bytes)
        bytes.append(contentsOf: UInt16(encryptedData.count).bytes)
        bytes.append(contentsOf: encryptedData)
        return bytes
    }
}
