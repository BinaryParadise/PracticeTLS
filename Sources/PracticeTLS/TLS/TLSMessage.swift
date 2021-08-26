//
//  TLSMessage.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation

public class TLSMessage: Streamable {
    var type: TLSMessageType = .handeshake
    var version: TLSVersion = TLSVersion.V1_2
    var rawData: [UInt8]?

    /// 握手协议内容长度（不包括协议头）
    var contentLength: UInt16 = 0
    
    init() {
        
    }
    
    required init?(stream: DataStream) {
        rawData = stream.data
        type = TLSMessageType(rawValue: stream.readByte() ?? 0) ?? .handeshake
        version = TLSVersion(rawValue: stream.readUInt16() ?? 0x303)
        contentLength = stream.readUInt16() ?? 0
    }
    
    func dataWithBytes() -> [UInt8] {
        return []
    }
    
    func messageData() -> [UInt8] {
        if let rawData = rawData {
            return [UInt8](rawData[5...])
        }
        return [UInt8](dataWithBytes()[5...])
    }
}
