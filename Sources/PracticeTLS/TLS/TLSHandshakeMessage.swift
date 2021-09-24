//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSHandshakeMessage: TLSMessage {
    var handshakeType: TLSHandshakeType {
        switch type {        
        case .handshake(let handshakeType):
            return handshakeType
        default:
            fatalError("")
        }
    }
    
    init(_ type: TLSHandshakeType, context: TLSConnection? = nil) {
        super.init(.handshake(type), context: context)
    }
    
    public override init?(stream: DataStream, context: TLSConnection) {
        guard let handshakeType = TLSHandshakeType(rawValue: stream.readByte() ?? UInt8.max) else { return nil}
        super.init(stream: stream, context: context)
        type = .handshake(handshakeType)
        stream.readUInt24()
    }
    
    class func handshakeMessageFromData(data: [UInt8], context: TLSConnection) -> TLSMessage? {
        guard let header = readHeader(stream: data.stream) else {
            var msg = TLSHandshakeMessage(stream: data.stream, context: context)
            msg?.type = .handshake(.finished)
            return msg
        }
        
        var message: TLSHandshakeMessage?
        switch header.type {
        case .helloRequest, .helloRetryRequest:
            break
        case .clientHello:
            message = TLSClientHello(stream: data.stream, context: context)
        case .serverHello:
            break
        case .certificate:
            break
        case .serverKeyExchange:
            break
        case .certificateRequest:
            break
        case .serverHelloDone:
            break
        case .certificateVerify:
            break
        case .clientKeyExchange:
            message = TLSClientKeyExchange(stream: data.stream, context: context)
        case .finished:
            message = TLSFinished(stream: data.stream, context: context)
        case .encryptedExtensions, .messageHash:
            break
        }
        return message
    }
    
    func writeHeader(data: inout [UInt8]) {
        data.insert(contentsOf: UInt(data.count).bytes[1...3], at: 0)
        data.insert(handshakeType.rawValue, at: 0)
    }
    
    class func readHeader(stream: DataStream) -> (type: TLSHandshakeType, bodyLength: Int)? {
        if let type = stream.readByte(),
           let handshakeType = TLSHandshakeType(rawValue: type),
           let bodyLength = stream.readUInt24(), bodyLength > 0 {
            return (handshakeType, bodyLength)
        }
        return nil
    }
}
