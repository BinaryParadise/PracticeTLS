//
//  TLSMessage.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Foundation

public class TLSMessage: Streamable {
    var type: TLSMessageType = .handshake(.clientHello)
    
    var contentType: ContentType {
        switch type {
        case .changeCipherSpec:
            return .changeCipherSpec
        case .handshake(_):
            return .handshake
        case .alert:
            return .alert
        case .applicationData:
            return .applicationData
        }
    }
    
    var nextMessage: TLSMessage?
    
    /// 默认版本TLS 1.2
    var version: TLSVersion = .V1_2
    var rawData: [UInt8] = []
    
    var rwtag: RWTags {
        switch type {
        case .changeCipherSpec:
            return .changeCipherSpec
        case .handshake(let handshakeType):
            return (self is TLSHelloRetryRequest) ? .handshake(.helloRetryRequest) : .handshake(handshakeType)
        case .alert:
            return .alert
        case .applicationData:
            return .applicationData
        }
    }
    
    var context: TLSConnection?
    
    init(_ type : TLSMessageType = .handshake(.clientHello), context: TLSConnection? = nil) {
        self.type = type
        self.context = context
    }
    
    public init?(stream: DataStream, context: TLSConnection) {
        rawData = stream.data
    }
    
    public class func fromData(data: [UInt8], context: TLSConnection) -> TLSMessage? {
        let stream = data.stream
        guard let contentType = ContentType(rawValue: stream.readByte() ?? 0) else { return nil}
        stream.readUInt16()
        let contentLength = stream.readUInt16() ?? 0
        let contentData = stream.read(count: contentLength) ?? []
        return fromData(data: contentData, context: context, contentType: contentType)
    }
    
    public class func fromData(data: [UInt8], context: TLSConnection, contentType: ContentType) -> TLSMessage? {
        let stream = data.stream
        switch contentType {
        case .changeCipherSpec:
            return TLSChangeCipherSpec(stream: stream, context: context)
        case .alert:
            return TLSAlert(stream: stream, context: context)
        case .handshake:
            return TLSHandshakeMessage.handshakeMessageFromData(data: data, context: context)
        case .applicationData:
            return TLSApplicationData(stream: stream, context: context)
        }
    }
    
    func dataWithBytes() -> [UInt8] {
        return rawData
    }
}
