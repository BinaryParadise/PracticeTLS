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
public class DataStream {
    private var origin: [UInt8] = []
    var data: [UInt8] {
        return origin
    }
    
    /// 当前读取位置，默认为0
    public var position: Int = 0
    
    public var endOfStream: Bool {
        return position >= origin.count
    }
    
    public init(_ data: Data, offset: Int = 0) {
        self.origin = data.bytes
        read(count: offset)
    }
    
    public init(_ bytes: [UInt8], offset: Int = 0) {
        self.origin = bytes
        read(count: offset)
    }
    
    /// 重置读取
    public func reset() {
        position = 0
    }
    
    @discardableResult public func read(count: UInt8, cursor: Bool = true) -> [UInt8]? {
        return read(count: Int(count))
    }
    
    @discardableResult public func read(count: UInt16, cursor: Bool = true) -> [UInt8]? {
        return read(count: Int(count), cursor: true)
    }
    
    ///读取指定数量字节
    @discardableResult public func read(count: Int, cursor: Bool = true) -> [UInt8]? {
        if position+count <= origin.count {
            let bytes = [UInt8](origin[position..<position+count])
            if cursor {
                position += bytes.count
            }
            return bytes
        }
        position = origin.count
        return nil
    }
    
    /// 读取到结束后重置到初始位置
    public func readToEnd() -> [UInt8]? {
        if position < origin.count {
            let bytes = [UInt8](origin[position..<origin.count])
            reset()
            return bytes
        }
        return nil
    }
    
    /// 读取一个字节
    public func readByte(cursor: Bool = true) -> UInt8? {
        return read(count: 1, cursor: cursor)?.first
    }
    
    /// 读取两个字节
    @discardableResult public func readUInt16(cursor: Bool = true) -> UInt16? {
        if let bytes = read(count: 2, cursor: cursor) {
            return UInt16(bytes[0]) << 8 + UInt16(bytes[1])
        }
        return nil
    }
    
    /// 读取三个字节
    @discardableResult public func readUInt24() -> Int? {
        if let bytes = read(count: 3) {
            return Int(bytes[0]) << 16 + Int(bytes[1]) << 8 + Int(bytes[2])
        }
        return nil
    }
    
    ///读取四个字节
    @discardableResult public func readUInt() -> UInt? {
        if let bytes = read(count: 4) {
            return UInt(bytes[0])  << 24 + UInt(bytes[1])  << 16 + UInt(bytes[2]) << 8 + UInt(bytes[3])
        }
        return nil
    }
}

protocol OutputStream {
    mutating func write(_ data: [UInt8])
    mutating func write(_ data: UInt8)
}

extension Int {
    public var bytes: [UInt8] {
        return UInt(self).bytes
    }
}

extension UInt {
    public var bytes: [UInt8] {
        return [UInt8(truncatingIfNeeded: self >> 24),
                UInt8(truncatingIfNeeded: self >> 16),
                UInt8(truncatingIfNeeded: self >> 8),
                UInt8(truncatingIfNeeded: self)]
    }
}

extension UInt64 {
    public var bytes: [UInt8] {
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
    public var bytes: [UInt8] {
        return [UInt8(truncatingIfNeeded: self >> 8),
                UInt8(truncatingIfNeeded: self)]
    }
}

extension Array where Element == UInt8 {
    public var intValue: Int {
        var r: Int = 0
        for (i, item) in reversed().enumerated() {
            r += Int(item << (i * 8))
        }
        return r
    }
    
    public var int64Value: Int64 {
        var r: Int64 = 0
        for (i, item) in reversed().enumerated() {
            r += Int64(item << (i * 8))
        }
        return r
    }
    
    public var stream: DataStream {
        return DataStream(self)
    }
    
    public var data: Data {
        return Data(self)
    }
}

extension Array: OutputStream where Element == UInt8 {
    mutating func write(_ data: UInt8) {
        append(data)
    }
    
    mutating func write(_ data: [UInt8]) {
        append(contentsOf: data)
    }
    
    mutating func write(_ data: SubSequence) {
        append(contentsOf: data)
    }
}

extension Decimal {
    var int: Int {
        return NSDecimalNumber(decimal: self).intValue
    }
}
