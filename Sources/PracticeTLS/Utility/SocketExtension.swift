//
//  SocketExtension.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import CocoaAsyncSocket

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

extension GCDAsyncSocket {
    func readData(tag: RWTags) -> Void {
        readData(withTimeout: -1, tag: tag.rawValue)
    }
    
    func writeData(data: [UInt8]?, tag: RWTags) -> Void {
        write(Data(data ?? []), withTimeout: -1, tag: tag.rawValue)
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
}
