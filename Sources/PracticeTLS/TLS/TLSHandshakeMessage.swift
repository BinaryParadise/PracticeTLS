//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

public class TLSHandshakeMessage: TLSMessage {
    var handshakeType: TLSHandshakeType = .clientHello
    
    public func responseMessage() -> TLSHandshakeMessage? {
        return nil
    }

    public override class func fromData(data: [UInt8]) -> TLSMessage? {
        guard let header = readHeader(stream: data.stream) else {
            return TLSEncryptedMessage(stream: data.stream)
        }
        
        var message: TLSHandshakeMessage?
        switch header.type {
        case .helloRequest, .helloRetryRequest:
            break
        case .clientHello:
            message = TLSClientHello(stream: data.stream)
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
            message = TLSClientKeyExchange(stream: data.stream)
        case .finished:
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
