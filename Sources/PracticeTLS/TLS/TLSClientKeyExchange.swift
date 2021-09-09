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
    var bodyLength: Int = 0
    private var preMasterSecret: EncryptedPreMasterSecret?
    var ecdhParams: ECDHServerParams?
    
    var preMasterKey: [UInt8] {
        if let preMasterSecret = preMasterSecret {
            return preMasterSecret.preMasterKey
        } else {
            return ecdhParams!.pubKey
        }
    }
    
    public override init?(stream: DataStream, context: TLSConnection) {
        super.init(stream: stream, context: context)
        switch context.keyExchange {
        case .rsa:
            preMasterSecret = EncryptedPreMasterSecret(stream)
        case .dhe:
            break
        case .ecdhe:
            ecdhParams = ECDHServerParams(stream: stream)
        }
    }
    
    override func messageData() -> [UInt8] {
        var bytes:[UInt8] = []
        bytes.append(handshakeType.rawValue)
        if let preMaster = preMasterSecret {
            bytes.append(contentsOf: UInt(preMaster.encryptedPreMaster.count + 2).bytes[1...3])
            bytes.append(contentsOf: UInt16(preMaster.encryptedPreMaster.count).bytes)
            bytes.append(contentsOf: preMaster.encryptedPreMaster)
        } else if let ecdhp = ecdhParams {
            bytes.append(contentsOf: UInt(ecdhp.pubKey.count + 2).bytes[1...3])
            bytes.append(UInt8(ecdhp.pubKey.count))
            bytes.append(contentsOf: ecdhp.pubKey)
        }
        return bytes
    }
}
