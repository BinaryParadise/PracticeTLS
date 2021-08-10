//
//  TLSClientKeyExchange.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import CryptorRSA

class EncryptedPreMasterSecret {
    var preLength: UInt16 = 0
    var clientVersion: TLSVersion = .V1_2
    var random: [UInt8] = []
    init(_ stream: DataStream) {
        preLength = stream.readUInt16()!
        let encryptedPreMaster = stream.read(count: Int(preLength))!
        if let decryptedPreMaster = RSAUtils.shared.decrypted(Data(encryptedPreMaster)) {
            let preStream = DataStream(decryptedPreMaster)
            clientVersion = TLSVersion(rawValue: preStream.readUInt16()!)
            random = preStream.read(count: 46) ?? []
        }
    }
}

class TLSClientKeyExchange: TLSHandshakeMessage {
    var bodyLength: Int = 0
    var preMasterSecret: EncryptedPreMasterSecret
    required init?(stream: DataStream) {
        stream.position = 5
        let _handshakeType = TLSHandshakeType(rawValue: stream.readByte()!)!
        bodyLength = stream.readUInt24()!
        preMasterSecret = EncryptedPreMasterSecret(stream)
        super.init(stream: stream)
        handshakeType = _handshakeType
    }
}
