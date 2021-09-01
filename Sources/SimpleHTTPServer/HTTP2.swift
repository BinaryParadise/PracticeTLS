//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/31.
//

import Foundation
import PracticeTLS
import NIOHPACK
import NIOCore
import CryptoSwift

enum HTTP2 {}

extension HTTP2 {
    
    enum FrameType: UInt8 {
        case DATA          = 0x0
        case HEADERS       = 0x1
        case PRIORITY      = 0x2
        case RST_STREAM    = 0x3
        case SETTINGS      = 0x4
        case PUSH_PROMISE  = 0x5
        case PING          = 0x6
        case GOAWAY        = 0x7
        case WINDOW_UPDATE = 0x8
        case CONTINUATION  = 0x9
    }
    
    struct FrameFlags: OptionSet, CustomStringConvertible {
        typealias RawValue = UInt8
        private(set) var rawValue: UInt8
        
        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }
        
        /// END_STREAM flag. Valid on DATA and HEADERS frames.
        static let endStream     = FrameFlags(rawValue: 0x01)

        /// ACK flag. Valid on SETTINGS and PING frames.
        static let ack           = FrameFlags(rawValue: 0x01)

        /// END_HEADERS flag. Valid on HEADERS, CONTINUATION, and PUSH_PROMISE frames.
        static let endHeaders    = FrameFlags(rawValue: 0x04)

        /// PADDED flag. Valid on DATA, HEADERS, CONTINUATION, and PUSH_PROMISE frames.
        ///
        /// NB: swift-nio-http2 does not automatically pad outgoing frames.
        static let padded        = FrameFlags(rawValue: 0x08)

        /// PRIORITY flag. Valid on HEADERS frames, specifically as the first frame sent
        /// on a new stream.
        static let priority      = FrameFlags(rawValue: 0x20)

        // useful for test cases
        static var allFlags: FrameFlags = [.endStream, .endHeaders, .padded, .priority]
        
        var description: String {
            var strings: [String] = []
            for i in 0..<8 {
                let flagBit: UInt8 = 1 << i
                if (self.rawValue & flagBit) != 0 {
                    strings.append(String(flagBit, radix: 16, uppercase: true))
                }
            }
            return "[\(strings.joined(separator: ", "))]"
        }
    }
    
    class Frame {
        var length: Int = 0
        var type: FrameType = .HEADERS
        var flags: FrameFlags = []
        var R: Bool = false
        var streamIdentifier: UInt = 0
        var payload: [UInt8] = []
        var nextFrame: Frame?
        
        init() {
            //streamIdentifier = UInt(AES.randomIV(4).intValue & 0x7FFFFFFF)
        }
        
        init(_ data: [UInt8]) {
            let stream = DataStream(data)
            length = stream.readUInt24() ?? 0
            type = FrameType(rawValue: stream.readByte()!) ?? .DATA
            flags = FrameFlags(rawValue: stream.readByte()!)
            streamIdentifier = stream.readUInt()! & 0x7FFFFFFF
            R = (streamIdentifier & 0x80000000) != 0
            payload = stream.read(count: length) ?? []
        }
        
        func rawBytes() -> [UInt8] {
            var bytes: [UInt8] = []
            bytes.append(contentsOf: UInt(payload.count).bytes[1...])
            bytes.append(type.rawValue)
            bytes.append(flags.rawValue)
            bytes.append(contentsOf: streamIdentifier.bytes)
            bytes.append(contentsOf: payload)
            return bytes
        }
        
        class func fromData(data: [UInt8]) -> Frame? {
            guard let type = FrameType(rawValue: data[3]) else { return nil}
            switch type {
            case .DATA:
                break
            case .HEADERS:
                return FrameHeaders(data)
            case .PRIORITY:
                break
            case .RST_STREAM:
                break
            case .SETTINGS:
                return FrameSettings(data)
            case .PUSH_PROMISE:
                break
            case .PING:
                break
            case .GOAWAY:
                break
            case .WINDOW_UPDATE:
                return FrameWindowUpdate(data)
            case .CONTINUATION:
                break
            }
            return nil
        }
    }
    
    class FrameSettings: Frame {
        var settings: [Setting] = []
        
        override init() {
            super.init()
            
            type = .SETTINGS
            
            settings = [
                Setting(identifier: .max_concurrent_streams, value: 100),
                Setting(identifier: .initial_windows_size, value: 0xFFFF)
            ]
            
            settings.forEach { set in
                payload.append(contentsOf: set.identifier.rawValue.bytes)
                payload.append(contentsOf: set.value.bytes)
            }
        }
        
        override init(_ data: [UInt8]) {
            super.init(data)
            let stream = DataStream(payload)
            while !stream.endOfStream {
                settings.append(Setting(identifier: .init(rawValue: stream.readUInt16()!)!, value: stream.readUInt()!))
            }
        }
        
        enum SettingIdentifier: UInt16 {
            case max_concurrent_streams = 0x0003
            case initial_windows_size = 0x0004
        }
        
        struct Setting {
            var identifier: SettingIdentifier
            var value: UInt
        }
    }
    
    class FrameWindowUpdate: Frame {
        var reserved: Bool = false
        var window_size_increment: UInt = 0xA00000
        
        override init() {
            super.init()
            
            type = .WINDOW_UPDATE
            payload.append(contentsOf: window_size_increment.bytes)
        }
        
        override init(_ data: [UInt8]) {
            super.init(data)
            let stream = DataStream(payload)
            window_size_increment = stream.readUInt()! & 0x7FFFFFFF
            reserved = (window_size_increment & 0x80000000) != 0
        }
    }
    
    class FrameHeaders: Frame {
        
        /// 填充大小
        var padLength: UInt8 = 0
        
        /// 流依赖是否排他
        var E: Bool = false
        
        /// 流依赖标识
        var streamDependency: UInt = 0
        /// 权重（优先级）
        var weight: UInt8 = 254
        var header: HPACKHeaders?
        var path: String = "/"
        
        override init(_ data: [UInt8]) {
            super.init(data)
            
            let stream = DataStream(payload)
            
            flags = [.endStream, .endHeaders, .priority]
            
            if flags.contains(.padded) {
                padLength = stream.readByte()!
            }
            
            streamDependency = stream.readUInt()! & 0x7FFFFFFF
            E = (streamDependency & 0x80000000) != 0
            
            var decoder = HPACKDecoder(allocator: ByteBufferAllocator())
            
            var buffer = ByteBufferAllocator().buffer(capacity: 1024)
            buffer.writeBytes(payload[5...])
            if let h = try? decoder.decodeHeaders(from: &buffer) {
                header = h
                if let x = h.first(name: "path") {
                    path = x
                }
            }
        }
        
        init(_ contentLength: Int, contentType: String) {
            super.init()
            
            type = .HEADERS
            flags = [.endStream, .endHeaders, .priority]
                        
            streamIdentifier = UInt(AES.randomIV(4).intValue & 0x7FFFFFFF)
            
            var h = HPACKHeaders()
            h.add(name: ":status", value: "200")
            h.add(name: "content-length", value: "\(contentLength)")
            h.add(name: "content-type", value: contentType)
            h.add(name: "server", value: "PracticeTLS")
            var encoder = HPACKEncoder(allocator: ByteBufferAllocator())
            var buffer = ByteBuffer()
            try? encoder.encode(headers: h, to: &buffer)
            var headerBlockFragment: [UInt8] = []
            if let bytes = buffer.readBytes(length: buffer.readableBytes) {
                headerBlockFragment.append(contentsOf: bytes)
            }
            payload = (flags.contains(.padded) ? [padLength] : []) + (UInt(E ? 1 : 0) | streamDependency).bytes + [weight] + headerBlockFragment
        }
    }
    
    class FrameData: Frame {
        var padLength: UInt8 = 0
        
        init(application data: [UInt8]) {
            super.init()
            type = .DATA
            flags = [.endStream]

            payload = (flags.contains(.padded) ? [padLength] : []) + data
        }
    }
}
