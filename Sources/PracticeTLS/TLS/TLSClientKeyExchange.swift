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
    var preMasterKey: [UInt8] = []
    init(_ stream: DataStream) {
        preLength = stream.readUInt16()!
        BigInt.withContext { _ in
            let encryptedPreMaster = stream.read(count: Int(preLength))!
            let rsa = RSAEncryptor()
            do {
                let preMasterSecret = try rsa.decryptData(data: encryptedPreMaster)
                let preStream = DataStream(Data(preMasterSecret))
                //self.clientVersion = TLSVersion(rawValue: preStream.readUInt16()!)
                self.preMasterKey = preStream.read(count: 48) ?? []
            } catch {
                LogError("预备密匙解密失败：\(error)")
            }
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
}
