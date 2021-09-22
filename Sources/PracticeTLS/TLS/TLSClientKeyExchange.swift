//
//  TLSClientKeyExchange.swift
//  
//
//  Created by Rake Yang on 2021/8/10.
//

import Foundation
import SecurityRSA

class EncryptedPreMasterSecret {
    var encryptedPreMaster: [UInt8] = []
    var preMasterKey: [UInt8] = []
    init?(_ stream: DataStream) {
        guard let l = stream.readUInt16() else {return nil}
        encryptedPreMaster = stream.read(count: Int(l))!
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
    private var preMasterSecret: EncryptedPreMasterSecret?
    private var ecdhParams: ECDHServerParams?
    
    public override init?(stream: DataStream, context: TLSConnection) {
        super.init(stream: stream, context: context)
        switch context.keyExchange {
        case .rsa:
            preMasterSecret = EncryptedPreMasterSecret(stream)
            context.preMasterKey = preMasterSecret!.preMasterKey
            context.record.keyExchange(algorithm: .rsa, preMasterSecret: context.preMasterKey)
        case .ecdha(let encryptor):
            ecdhParams = ECDHServerParams(stream: stream)
            context.preMasterKey = ecdhParams!.pubKey
            if let preMasterSecret = try? encryptor.keyExchange(context.preMasterKey) {
                context.record.keyExchange(algorithm: .ecdhe, preMasterSecret: preMasterSecret)
            }
        }
    }
}
