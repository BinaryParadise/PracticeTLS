//
//  DataStream.swift
//  
//
//  Created by Rake Yang on 2021/8/6.
//

import Foundation

protocol Streamable {
    func dataWithBytes() -> [UInt8]
}

/// Data读取流
class DataStream {
    private var origin: [UInt8] = []
    var data: [UInt8] {
        return origin
    }
    
    /// 当前读取位置，默认为0
    var position: Int = 0
    
    init(_ data: Data) {
        self.origin = data.bytes
    }
    
    init(_ bytes: [UInt8]) {
        self.origin = bytes
    }
    
    /// 重置读取
    func reset() {
        position = 0
    }
    
    ///读取指定数量字节
    func read(count: Int) -> [UInt8]? {
        if position+count <= origin.count {
            let bytes = [UInt8](origin[position..<position+count])
            position += bytes.count
            return bytes
        }
        reset()
        return nil
    }
    
    /// 读取到结束后重置到初始位置
    func readToEnd() -> [UInt8]? {
        if position < origin.count {
            let bytes = [UInt8](origin[position..<origin.count])
            reset()
            return bytes
        }
        return nil
    }
    
    /// 读取一个字节
    func readByte() -> UInt8? {
        return read(count: 1)?.first
    }
    
    /// 读取两个字节
    func readUInt16() -> UInt16? {
        if let bytes = read(count: 2) {
            return UInt16(bytes[0]) << 8 + UInt16(bytes[1])
        }
        return nil
    }
    
    /// 读取三个字节
    func readUInt24() -> Int? {
        if let bytes = read(count: 3) {
            return Int(bytes[0]) << 16 + Int(bytes[1]) << 8 + Int(bytes[2])
        }
        return nil
    }
    
    ///读取四个字节
    func readUInt() -> UInt? {
        if let bytes = read(count: 4) {
            return UInt(bytes[0])  << 24 + UInt(bytes[1])  << 16 + UInt(bytes[2]) << 8 + UInt(bytes[3])
        }
        return nil
    }
}

extension UInt {
    var bytes: [UInt8] {
        return [UInt8(truncatingIfNeeded: self >> 24),
                UInt8(truncatingIfNeeded: self >> 16),
                UInt8(truncatingIfNeeded: self >> 8),
                UInt8(truncatingIfNeeded: self)]
    }
}

extension UInt64 {
    var bytes: [UInt8] {
        return [UInt8(truncatingIfNeeded: self >> 56),
                UInt8(truncatingIfNeeded: self >> 48),
                UInt8(truncatingIfNeeded: self >> 40),
                UInt8(truncatingIfNeeded: self >> 32),
                UInt8(truncatingIfNeeded: self >> 24),
                UInt8(truncatingIfNeeded: self >> 16),
                UInt8(truncatingIfNeeded: self >> 8),
                UInt8(truncatingIfNeeded: self)]
    }
}

extension UInt16 {
    var bytes: [UInt8] {
        return [UInt8(truncatingIfNeeded: self >> 8),
                UInt8(truncatingIfNeeded: self)]
    }
}
