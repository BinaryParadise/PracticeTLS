//
//  SocketExtension.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import Socket
import Foundation

/// 数据读写标记
enum RWTags {
    case changeCipherSpec
    case handshake(TLSHandshakeType)
    case alert
    case applicationData
    case fragment
    case custom(UInt8)
    
    init(rawValue: UInt8) {
        switch rawValue {
        case 0...20: self = .handshake(TLSHandshakeType(rawValue: rawValue)!)
        case 21: self = .changeCipherSpec
        case 22: self = .alert
        case 23: self = .applicationData
        case 30: self = .fragment
        default: self = .custom(rawValue)
        }
    }
    
    var rawValue: Int {
        switch self {
        case .changeCipherSpec:
            return 21
        case .handshake(let type):
            return Int(type.rawValue)
        case .alert:
            return 22
        case .applicationData:
            return 23
        case .fragment:
            return 30
        case .custom(let v):
            return Int(v)
        }
    }
}

extension Socket: TLSSocketStream {
    func readData(_ tag: RWTags) -> [UInt8] {
        //LogDebug("读取前: \(Thread.current)")
        var buffer: Data = Data()
        do {
            try read(into: &buffer)
            //LogDebug("读取后: \(Thread.current)")
            return buffer.bytes
        } catch {
            //LogError("\(error)")
        }
        return []
    }
    
    func writeData(_ data: [UInt8]?, tag: RWTags) {
        guard let data = data else { return }
        //LogDebug("写入前: \(Thread.current)")
        do {
            try write(from: Data(data))
            //LogDebug("写入后: \(Thread.current)")
        } catch {
            LogError("\(error)")
        }
    }
    
    func disconnect() {
        close()
    }
}

extension Array where Element == UInt8 {
    public func toHexArray() -> String {
        `lazy`.reduce(into: "") {
            var s = String($1, radix: 16).uppercased()
            if s.count == 1 {
                s = "0" + s
            }
            $0 += "0x\(s), "
        }
    }
        
    /// 16进制字符串
    /// - Returns: e.g 5ce7bebe65fe2c8308e03df170fbbd38b6a440fc3939b0d8090bee4a61e738c5
    public func toHexString() -> String {
        `lazy`.reduce(into: "") {
            var s = String($1, radix: 16).uppercased()
            if s.count == 1 {
                s = "0" + s
            }
            $0 += "\(s)"
        }
    }
    
    public func toString(_ encoding: String.Encoding = .utf8) -> String {
        return String(data: Data(self), encoding: encoding) ?? ""
    }
}
