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

    public class func fromData(data: Data) -> TLSHandshakeMessage? {
        guard let header = readHeader(stream: DataStream(data)) else {
            return nil
        }
        
        //TODO:内容大小验证
//        if data.count > header.bodyLength + 4  {
//            return nil
//        }
        var message: TLSHandshakeMessage?
        switch header.type {
        case .helloRequest, .helloRetryRequest:
            break
        case .clientHello:
            message = TLSClientHello(stream: DataStream(data))
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
            message = TLSClientKeyExchange(stream: DataStream(data))
            break
        case .finished:
            break
        }
        return message
    }
    
    class func readHeader(stream: DataStream) -> (type: TLSHandshakeType, bodyLength: Int)? {
        _ = stream.read(count: 5)
        if let type = stream.readByte(),
           let handshakeType = TLSHandshakeType(rawValue: type),
           let bodyLength = stream.readUInt24() {
            return (handshakeType, bodyLength)
        }
        return nil
    }
}
