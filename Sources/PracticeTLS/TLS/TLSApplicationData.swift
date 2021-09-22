//
//  File.swift
//  
//
//  Created by Rake Yang on 2021/8/25.
//

import Foundation

class TLSApplicationData: TLSMessage {
    
    init(plantData: [UInt8]) {
        super.init(.applicationData)
        rawData = plantData
    }
    
    init(_ data: [UInt8], context: TLSConnection) {
        super.init(.applicationData)
        if context.record.serverCipherChanged, let ed = context.record.encrypt(data, contentType: .applicationData, iv: nil) {
            rawData = ed
        }
    }
    
    init(_ msg: TLSMessage, context: TLSConnection) {
        super.init(.applicationData)        
        if context.record.serverCipherChanged, let ed = context.record.encrypt(msg.dataWithBytes(), contentType: msg.contentType, iv: nil) {
            rawData = ed
        }
        nextMessage = msg.nextMessage
    }
    
    override init?(stream: DataStream, context: TLSConnection) {
        super.init(.applicationData, context: context)
        rawData = stream.readToEnd() ?? []
    }
}
