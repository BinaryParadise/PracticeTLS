//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/9/24.
//

import Foundation

extension QUIC {
    class PacketInitial: Packet {
        override init(_ data: [UInt8]) {
            super.init(data)
            
            let stream = data.stream
            stream.readByte()
            
            if flag >> 7 == 1 {
                version = Version(rawValue: stream.readUInt()!)
            }
            
            destinationCId = stream.quicReadVariable()
            sourceCID = stream.quicReadVariable()
            token = stream.quicReadVariable()
            let length = stream.quicReadVariable(false)?.intValue ?? 0
            number = stream.quicReadVariable(false)?.intValue ?? 0
            payload = stream.read(count: length) ?? []
        }
    }
}
