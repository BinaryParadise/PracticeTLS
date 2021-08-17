//
//  SocketExtension.swift
//  
//
//  Created by Rake Yang on 2021/8/5.
//

import CocoaAsyncSocket

/// 数据读写标记
enum RWTags {
    case handshake(TLSHandshakeType)
    case http
    
    init(rawValue: UInt8) {
        if rawValue == 0 {
            self = .http
        } else {
            self = .handshake(TLSHandshakeType(rawValue: rawValue) ?? .clientHello)
        }
    }
    
    var rawValue: Int {
        switch self {
        case .handshake(let handshakeType):
            return Int(handshakeType.rawValue)
        case .http:
            return Int(UInt8.zero)
        }
    }
}

extension GCDAsyncSocket {
    func readData(tag: RWTags) -> Void {
        readData(withTimeout: 5, tag: tag.rawValue)
    }
    
    func writeData(data: [UInt8]?, tag: RWTags) -> Void {
        write(Data(data ?? []), withTimeout: 5, tag: tag.rawValue)
    }
}

extension Array where Element == UInt8 {

  public func toHexArray() -> String {
    `lazy`.reduce(into: "") {
      var s = String($1, radix: 16)
      if s.count == 1 {
        s = "0" + s
      }
      $0 += "0x\(s), "
    }
  }
}
