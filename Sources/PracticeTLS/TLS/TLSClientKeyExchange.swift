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
    var encryptedPreMaster: [UInt8] = []
    init(_ stream: DataStream) {
        preLength = stream.readUInt16()!
        BigInt.withContext { _ in
            self.encryptedPreMaster = stream.read(count: Int(preLength))!
            //TODO: 解密预备主密匙
            /*let identity = PEMFileIdentity(certificateFile: Bundle.certBundle().path(forResource: "Cert/localhost.crt", ofType: nil)!, privateKeyFile: Bundle.certBundle().path(forResource: "Cert/private.pem", ofType: nil)!)
            if let rsa = identity?.signer(with: .sha256) as? RSA {
                do {
                    let decryptedPreMaster = try rsa.decrypt(encryptedPreMaster)
                    let preStream = DataStream(Data(decryptedPreMaster))
                    self.clientVersion = TLSVersion(rawValue: preStream.readUInt16()!)
                    self.random = preStream.read(count: 46) ?? []
                } catch {
                    LogError("预备密匙解密失败：\(error)")
                }
            }*/
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
        res.encryptedMessage = encryptedMessage
        return res
    }
}
