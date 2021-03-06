//
//  TLSServerKeyExchange.swift
//  
//
//  Created by Rake Yang on 2021/9/8.
//

import Foundation
import _CryptoExtras

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
        
        let signPadding: _RSA.Signing.Padding = (serverHello.context?.negotiatedProtocolVersion == .V1_3) ? .PSS : .insecurePKCS1v1_5
        
        //踩坑：想当然的以为只有pubkey需要签名⚠️⚠️⚠️
        let plantData = serverHello.client!.random.dataWithBytes()+serverHello.random.dataWithBytes()+params.dataWithBytes()
        signedData = try TLSSignedData(hashAlgorithm: .sha256, signatureAlgorithm: .rsa, signature: RSAEncryptor.shared.sign(data: plantData, algorithm: signPadding))
        //signedData.signature[0] = 0x0a
        super.init(.serverKeyExchange)
        nextMessage = TLSServerHelloDone()
    }
    
    required init?(stream: DataStream) {
        fatalError()
    }
    
    override func dataWithBytes() -> [UInt8] {
        var b: [UInt8] = []
        b.append(contentsOf: params.dataWithBytes())
        b.append(contentsOf: signedData.bytes)
        writeHeader(data: &b)
        return b
    }
}
