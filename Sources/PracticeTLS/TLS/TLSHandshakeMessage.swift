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
    var clientVersion: TLSVersion = .V1_2
    var nextMessage: TLSHandshakeMessage?
    var encrypted: [UInt8] = []
    
    init(_ type: TLSHandshakeType = .clientHello) {
        super.init(.handshake(type))
    }
    
    public override init?(stream: DataStream, context: TLSConnection) {
        super.init(stream: stream, context: context)
        type = .handshake(TLSHandshakeType(rawValue: stream.readByte() ?? UInt8.max) ?? .clientHello)
        stream.readUInt24()
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(type.rawValue)
        bytes.append(contentsOf: version.rawValue.bytes)
        bytes.append(contentsOf: UInt16(encrypted.count).bytes)
        
        bytes.append(contentsOf: encrypted)
        return bytes
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
        case .encryptedExtensions, .finished:
            break
        }
        return message
    }
    
    class func readHeader(stream: DataStream) -> (type: TLSHandshakeType, bodyLength: Int)? {
        _ = stream.read(count: 5)
        if let type = stream.readByte(),
           let handshakeType = TLSHandshakeType(rawValue: type),
           let bodyLength = stream.readUInt24(), bodyLength > 0 {
            return (handshakeType, bodyLength)
        }
        return nil
    }
}
