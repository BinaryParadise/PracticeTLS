//
//  TLSClientKeyExchange.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import SecurityRSA

class EncryptedPreMasterSecret {
    var preLength: UInt16 = 0
    var encryptedPreMaster: [UInt8] = []
    var preMasterKey: [UInt8] = []
    init(_ stream: DataStream) {
        preLength = stream.readUInt16()!
        encryptedPreMaster = stream.read(count: Int(preLength))!
        let rsa = RSAEncryptor()
        do {
            let preMasterSecret = try rsa.decryptData(data: encryptedPreMaster)
            self.preMasterKey = preMasterSecret
        } catch {
            LogError("预备密匙解密失败：\(error)")
        }
    }
}

class TLSClientKeyExchange: TLSHandshakeMessage {
    var bodyLength: Int = 0
    var preMasterSecret: EncryptedPreMasterSecret
    var encryptedMessage: TLSEncryptedMessage?
    
    required init?(stream: DataStream) {
        stream.position = 5
        let _handshakeType = TLSHandshakeType(rawValue: stream.readByte()!)!
        bodyLength = stream.readUInt24()!
        preMasterSecret = EncryptedPreMasterSecret(stream)
        super.init(stream: DataStream(stream.data))
        handshakeType = _handshakeType
        
        _ = stream.read(count: 6)
        encryptedMessage = TLSEncryptedMessage(stream: DataStream(Data(stream.readToEnd() ?? [])))
    }
    
    override func responseMessage() -> TLSHandshakeMessage? {
        let res = TLSChangeCipherSpec()
        return res
    }
    
    override func messageData() -> [UInt8] {
        var bytes:[UInt8] = []
        bytes.append(handshakeType.rawValue)
        bytes.append(contentsOf: UInt(bodyLength).bytes()[1...3])
        bytes.append(contentsOf: preMasterSecret.preLength.bytes())
        bytes.append(contentsOf: preMasterSecret.encryptedPreMaster)
        return bytes
    }
}
