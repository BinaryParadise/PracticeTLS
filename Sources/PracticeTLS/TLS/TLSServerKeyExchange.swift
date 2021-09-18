//
//  TLSServerKeyExchange.swift
//  
//
//  Created by Rake Yang on 2021/9/8.
//

import Foundation
import SecurityRSA

enum CurveType: UInt8 {
    case named_curve = 0x03
}

class ECDHServerParams: Streamable {
    var curveType: CurveType = .named_curve
    var namedCurve: NamedGroup = selectedCurve
    var pubKey: [UInt8] = []
    
    init(_ pubKey: [UInt8]) throws {
        self.pubKey = pubKey
    }
    
    required init?(stream: DataStream) {
        if let l = stream.readByte() {
            pubKey = stream.read(count: l) ?? []
        }
    }
    
    func parametersData() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(curveType.rawValue)
        bytes.append(contentsOf: namedCurve.rawValue.bytes)
        bytes.append(UInt8(pubKey.count))
        bytes.append(contentsOf: pubKey)
        return bytes
    }
    
    func dataWithBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(curveType.rawValue)
        bytes.append(contentsOf: namedCurve.rawValue.bytes)
        bytes.append(UInt8(pubKey.count))
        bytes.append(contentsOf: pubKey)
        return bytes
    }
}

class TLSServerKeyExchange: TLSHandshakeMessage {
    
    var params: ECDHServerParams
    var signedData: TLSSignedData
    
    init(_ cipherSuite: CipherSuite, pubKey: [UInt8], serverHello: TLSServerHello) throws {
        if pubKey.count == 0 {
            throw TLSError.error("param error")
        }
        params = try ECDHServerParams(pubKey)
        
        //踩坑：想当然的以为只有pubkey需要签名⚠️⚠️⚠️
        let plantData = serverHello.client!.random.dataWithBytes()+serverHello.random.dataWithBytes()+params.parametersData()
        signedData = try TLSSignedData(hashAlgorithm: .sha256, signatureAlgorithm: .rsa, signature: RSAEncryptor().sign(data: plantData))
        //signedData.signature[0] = 0x0a
        super.init(.handshake(.serverKeyExchange))
        nextMessage = TLSServerHelloDone()
    }
    
    required init?(stream: DataStream) {
        fatalError()
    }
    
    override func dataWithBytes() -> [UInt8] {
        var b: [UInt8] = []
        let length = UInt16(params.dataWithBytes().count + signedData.bytes.count)
        b.append(type.rawValue)
        b.append(contentsOf: version.rawValue.bytes)
        b.append(contentsOf: (length+4).bytes)
        
        b.append(handshakeType.rawValue)
        b.append(contentsOf: Int(length).bytes[1...])
        b.append(contentsOf: params.dataWithBytes())
        b.append(contentsOf: signedData.bytes)
        return b
    }
}
