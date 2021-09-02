//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/31.
//

import Foundation
import PracticeTLS
import CryptoSwift

enum H2 {}

extension H2 {
    
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
                return FrameGoaway(data)
            case .WINDOW_UPDATE:
                return FrameWindowUpdate(data)
            case .CONTINUATION:
                break
            }
            return nil
        }
    }
}
