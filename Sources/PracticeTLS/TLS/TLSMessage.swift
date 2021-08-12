//
//  TLSMessage.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation

public class TLSMessage: Streamable {
    var type: TLSMessageType = .handeshake
    var version: TLSVersion = TLSVersion.V1_0
    
    /// 握手协议内容长度（不包括协议头）
    var contentLength: UInt16 = 0
    
    init() {
        
    }
    
    required init?(stream: DataStream) {
        type = TLSMessageType(rawValue: stream.readByte()!) ?? .handeshake
        version = TLSVersion(rawValue: stream.readUInt16() ?? 0x303)
        contentLength = stream.readUInt16() ?? 0
    }
    
    func dataWithBytes() -> Data {
        return Data()
    }
}
