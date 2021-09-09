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
    var rawData: [UInt8] = []

    /// 握手协议内容长度（不包括协议头）
    var contentLength: UInt16 = 0
    
    init(_ type : TLSMessageType = .handeshake) {
        self.type = type
    }
    
    public init?(stream: DataStream, context: TLSConnection) {
        type = TLSMessageType(rawValue: stream.readByte()!) ?? .handeshake
        version = TLSVersion(rawValue: stream.readUInt16()!)
        stream.readUInt16()
        rawData = stream.data
    }
    
    public class func fromData(data: [UInt8], context: TLSConnection) -> TLSMessage? {
        let stream = data.stream
        guard let type = TLSMessageType(rawValue: stream.readByte(cursor: false) ?? 0) else { return nil}
        switch type {
        case .changeCipherSpec:
            return TLSChangeCipherSpec(stream: stream, context: context)
        case .alert:
            return TLSAlert(stream: stream, context: context)
        case .handeshake:
            return TLSHandshakeMessage.handshakeMessageFromData(data: data, context: context)
        case .applicatonData:
            return TLSApplicationData(stream: stream, context: context)
        }
    }
    
    func dataWithBytes() -> [UInt8] {
        return []
    }
    
    func messageData() -> [UInt8] {
        if rawData.count > 0 {
            return [UInt8](rawData[5...])
        }
        return [UInt8](dataWithBytes()[5...])
    }
}
