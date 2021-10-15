//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/2.
//

import Foundation
import PracticeTLS
import Crypto
import SwiftHpack

extension H2 {
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
    
    class FrameHeaders: Frame, HeaderListener {
        
        /// 填充大小
        var padLength: UInt8 = 0
        
        /// 流依赖是否排他
        var E: Bool = false
        
        /// 流依赖标识
        var streamDependency: UInt = 0
        /// 权重（优先级）
        var weight: UInt8 = 254
        var headers: [Header] = []
        var path: String = "/"
        static let encoder = HPACKEncoder(maxCapacity: 256*8)
        static let decoder = HPACKDecoder(maxHeaderSize: 256*8, maxHeaderTableSize: 256*8)
        
        override init(_ data: [UInt8]) {
            super.init(data)
            
            let stream = DataStream(payload)
            
            flags = [.endStream, .endHeaders, .priority]
            
            if flags.contains(.padded) {
                padLength = stream.readByte()!
            }
            
            streamDependency = stream.readUInt()! & 0x7FFFFFFF
            E = (streamDependency & 0x80000000) != 0
                        
            do {
                try FrameHeaders.decoder.decode(input: Bytes(existingBytes: Array(payload[5...])), headerListener: self)
                path = headers.first(where: { h in
                    h.name == ":path"
                })?.value ?? "/"
            } catch {
                LogError("Header解压失败： \(error)")
            }
        }
        
        init(_ contentLength: Int, contentType: String) {
            super.init()
            
            type = .HEADERS
            flags = [.endHeaders, .priority]
            
            let out = Bytes()
            do {
                try FrameHeaders.encoder.encodeHeader(out: out, name: ":status", value: "200")
                try FrameHeaders.encoder.encodeHeader(out: out, name: "content-length", value: "\(contentLength)")
                try FrameHeaders.encoder.encodeHeader(out: out, name: "content-type", value: contentType)
                try FrameHeaders.encoder.encodeHeader(out: out, name: "server", value: "PracticeTLS")
            } catch {
                LogError("Header压缩失败： \(error)")
            }
            payload = (flags.contains(.padded) ? [padLength] : []) + (UInt(E ? 1 : 0) | streamDependency).bytes + [weight] + out.data
        }
        
        func addHeader(name: [UInt8], value: [UInt8], sensitive: Bool) {
            headers.append(Header(name: name.toString(), value: value.toString()))
        }
        
        struct Header {
            var name: String
            var value: String
        }
    }
    
    class FrameData: Frame {
        var padLength: UInt8 = 0
        
        init(application data: [UInt8]) {
            super.init()
            type = .DATA
            flags = [.endStream]

            streamIdentifier = UInt(TLSRandomBytes(count: 4).intValue & 0x7FFFFFFF)

            payload = (flags.contains(.padded) ? [padLength] : []) + data
        }
    }
    
    enum ErrorCode: UInt {
        case NO_ERROR               = 0x0
        case PROTOCOL_ERROR         = 0x1
        case INTERNAL_ERROR         = 0x2
        case FLOW_CONTROL_ERROR     = 0x3
        case SETTINGS_TIMEOUT       = 0x4
        case STREAM_CLOSED          = 0x5
        case FRAME_SIZE_ERROR       = 0x6
        case REFUSED_STREAM         = 0x7
        case CANCEL                 = 0x8
        case COMPRESSION_ERROR      = 0x9
        case CONNECT_ERROR          = 0xa
        case ENHANCE_YOUR_CALM      = 0xb
        case INADEQUATE_SECURITY    = 0xc
        case HTTP_1_1_REQUIRED      = 0xd
    }
    
    class FrameGoaway: Frame {
        var lastStreamId: UInt = 0
        var errorCode: ErrorCode = .NO_ERROR
        var additionalDebugData: [UInt8] = []
        
        override init(_ data: [UInt8]) {
            super.init(data)
            
            let stream = DataStream(payload)
            
            lastStreamId = stream.readUInt()! & 0x7FFFFFFF
            errorCode = ErrorCode(rawValue: stream.readUInt()!) ?? .NO_ERROR
            additionalDebugData = stream.readToEnd() ?? []
        }
    }
    
    class FramePushPromise: Frame {
        var promisedStreamId: UInt = 3
        
        override init() {
            super.init()
        }
    }
}
