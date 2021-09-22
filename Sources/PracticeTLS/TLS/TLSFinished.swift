//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/24.
//

import Foundation

class TLSFinished: TLSHandshakeMessage {
    var verifyData: [UInt8] = []
    init(_ verifyData: [UInt8]) {
        self.verifyData = verifyData
        super.init(.finished)
    }
    
    override init?(stream: DataStream, context: TLSConnection) {
        super.init(stream: stream, context: context)
        
        verifyData = stream.readToEnd() ?? []
    }
    
    override func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.write(verifyData)
        writeHeader(data: &bytes)
        return bytes
    }
}
