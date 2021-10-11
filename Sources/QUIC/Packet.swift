//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/24.
//

import Foundation
import PracticeTLS

extension QUIC {
    enum PacketType: UInt8 {
        case initial = 0x00
        case zeroRTT = 0x01
        case handshake = 0x02
        case retry = 0x03
    }
    class Packet {
        var flag: UInt8
        var type: PacketType {
            return PacketType(rawValue: flag & 0x30) ?? .initial
        }
        var version: Version?
        var destinationCId: [UInt8]?
        var sourceCID: [UInt8]?
        var token: [UInt8]?
        var number: Int = 0
        var payload: [UInt8] = []
        
        var packetNumberLength: UInt64 {
            switch flag & 0x3 {
            case 0: return 1
            default:
                return 1
            }
        }
        
        init(_ data: [UInt8]) {
            flag = data[0]
        }
        
        class func fromData(_ data: [UInt8]) -> Packet? {
            guard let type = PacketType(rawValue: data[0] & 0x30) else {
                return nil
            }
            
            switch type {
            case .initial:
                return PacketInitial(data)
            case .zeroRTT:
                break
            case .handshake:
                break
            case .retry:
                break
            }
            return nil
        }
    }
}

extension DataStream {
    func quicReadVariable(_ readData: Bool = true) -> [UInt8]? {
        let b = readByte(cursor: false)!
        var length: [UInt8] = { () -> [UInt8]? in
            switch b & 0xC0 {
            case 0x00: return read(count: 1)
            case 0x40: return read(count: 2)
            case 0x80: return read(count: 4)
            case 0xC0: return read(count: 8)
            default: return read(count: 1)
            }
        }() ?? []
        length[0] = length[0] & 0x3F
        return readData ? read(count: length.intValue) : length
    }
}
