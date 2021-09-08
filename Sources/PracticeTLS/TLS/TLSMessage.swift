//
//  TLSMessage.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation

public class TLSMessage: Streamable {
    var type: TLSMessageType = .handeshake
    
    /// 默认版本TLS 1.2
    var version: TLSVersion = .V1_2
    var rawData: [UInt8]?

    /// 握手协议内容长度（不包括协议头）
    var contentLength: UInt16 = 0
    
    init() {
        
    }
    
    required init?(stream: DataStream) {
        stream.reset()
        rawData = stream.data
        type = TLSMessageType(rawValue: stream.readByte() ?? 0) ?? .handeshake
        version = TLSVersion(rawValue: stream.readUInt16() ?? 0x303)
        contentLength = stream.readUInt16() ?? 0
    }
    
    public class func fromData(data: [UInt8]) -> TLSMessage? {
        let stream = data.stream
        guard let type = TLSMessageType(rawValue: stream.readByte(cursor: false) ?? 0) else { return nil}
        switch type {
        case .changeCipherSpec:
            return TLSChangeCipherSpec(stream: stream)
        case .alert:
            return TLSAlert(stream: stream)
        case .handeshake:
            return TLSHandshakeMessage.fromData(data: data)
        case .applicatonData:
            return TLSApplicationData(stream: stream)
        }
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
